import base64
import datetime as dt
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import zlib

from durable import FORMAT, Journal, atomic_json, run_lock
import infra
import run_benchmark as bench
import watchdog
import worker


def artifact_view(job, result=None, ok=True):
    payload = {"ok": ok, "job": job}
    payload["result" if ok else "error"] = result if ok else "deliberate failure"
    encoded = base64.b64encode(zlib.compress(json.dumps(payload).encode())).decode()
    checksum = hashlib.sha256(encoded.encode()).hexdigest()
    return {"exitCode": 0 if ok else 1, "executionState": "Succeeded" if ok else "Failed",
            "output": f"BENCH_FILE:{job['job_id']}.b64:{len(encoded)}:{checksum}\nBENCH_DATA:{encoded}"}


class CredentialsTests(unittest.TestCase):
    ACCOUNT = "00000000-0000-0000-0000-000000000001/1234abcd"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        home = patch("infra.Path.home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.store = infra.FileCredentials()
        self.path = self.store.path / self.ACCOUNT.replace("/", "-")

    def test_platform_defaults_and_explicit_selection(self):
        for platform, expected in (("darwin", "keychain"), ("linux", "file")):
            with (self.subTest(platform=platform), patch("infra.sys.platform", platform),
                  patch("infra.KeychainCredentials") as keychain,
                  patch("infra.FileCredentials") as files):
                self.assertEqual(infra.default_credential_store(), expected)
                store = infra.Credentials()
                selected, other = (keychain, files) if expected == "keychain" else (files, keychain)
                self.assertIs(store.store, selected.return_value)
                other.assert_not_called()
                explicit = infra.Credentials("file" if expected == "keychain" else "keychain")
                self.assertIs(explicit.store, other.return_value)
        with self.assertRaisesRegex(RuntimeError, "Unknown credential store"):
            infra.Credentials("unsupported")

    def test_keychain_adapter_keeps_existing_operations(self):
        with patch("infra.KeychainCredentials") as backend:
            store = infra.Credentials("keychain")
            self.assertIs(store.create(self.ACCOUNT), backend.return_value.create.return_value)
            self.assertIs(store.get(self.ACCOUNT), backend.return_value.get.return_value)
            store.delete(self.ACCOUNT)
            backend.return_value.create.assert_called_once_with(self.ACCOUNT)
            backend.return_value.get.assert_called_once_with(self.ACCOUNT)
            backend.return_value.delete.assert_called_once_with(self.ACCOUNT)

    def test_keychain_is_not_replaced_silently_on_linux(self):
        with patch("infra.sys.platform", "linux"), patch("infra.ctypes.CDLL") as api:
            with self.assertRaisesRegex(RuntimeError, "original Mac"):
                infra.Credentials("keychain")
            api.assert_not_called()
        self.assertFalse(self.store.path.exists())

    def test_file_lifecycle_has_private_permissions_and_no_keychain_dependency(self):
        with patch("infra.sys.platform", "linux"), patch("infra.ctypes.CDLL") as api:
            store = infra.Credentials()
            value = store.create(self.ACCOUNT)
            self.assertRegex(value, r"^B9![A-Za-z0-9_-]{38}$")
            self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.read_text(), value + "\n")
            self.assertEqual(infra.Credentials().get(self.ACCOUNT), value)
            with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
                store.create(self.ACCOUNT)
            self.assertEqual(store.get(self.ACCOUNT), value)
            other_account = self.ACCOUNT.replace("1234abcd", "abcd1234")
            other_value = store.create(other_account)
            store.delete(self.ACCOUNT)
            self.assertFalse(self.path.exists())
            self.assertEqual(store.get(other_account), other_value)
            store.delete(other_account)
            store.delete(self.ACCOUNT)
            api.assert_not_called()

    def test_missing_credentials_do_not_create_a_directory(self):
        with self.assertRaisesRegex(RuntimeError, "missing"):
            self.store.get(self.ACCOUNT)
        self.store.delete(self.ACCOUNT)
        self.assertFalse(self.store.path.exists())

    def test_accounts_cannot_escape_the_credential_directory(self):
        for account in ("../outside", "/tmp/credential", self.ACCOUNT + "/../other"):
            for operation in (self.store.create, self.store.get, self.store.delete):
                with self.subTest(account=account, operation=operation.__name__):
                    with self.assertRaisesRegex(RuntimeError, "Invalid credential account"):
                        operation(account)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_unsafe_directory_permissions_or_owner_are_rejected(self):
        self.store.create(self.ACCOUNT)
        self.store.path.chmod(0o755)
        for operation in (self.store.create, self.store.get, self.store.delete):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(RuntimeError, "mode 0700"):
                    operation(self.ACCOUNT)
        self.store.path.chmod(0o700)
        with patch("infra.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(RuntimeError, "current user"):
                self.store.get(self.ACCOUNT)

    def test_unsafe_file_permissions_or_owner_are_rejected(self):
        self.store.create(self.ACCOUNT)
        self.path.chmod(0o644)
        for operation in (self.store.get, self.store.delete):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(RuntimeError, "mode 0600"):
                    operation(self.ACCOUNT)
        self.path.chmod(0o600)
        original_fstat = os.fstat

        def foreign_file(descriptor):
            info = original_fstat(descriptor)
            if info.st_ino == self.path.stat().st_ino:
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_uid=info.st_uid + 1)
            return info

        with patch("infra.os.fstat", side_effect=foreign_file):
            with self.assertRaisesRegex(RuntimeError, "current user"):
                self.store.get(self.ACCOUNT)

    def test_symlinked_directory_is_rejected(self):
        target = self.home / "other"
        target.mkdir(mode=0o700)
        self.store.path.symlink_to(target, target_is_directory=True)
        for operation in (self.store.create, self.store.get, self.store.delete):
            with self.subTest(operation=operation.__name__), self.assertRaises(OSError):
                operation(self.ACCOUNT)
        self.assertEqual(list(target.iterdir()), [])

    def test_symlinked_or_hardlinked_file_is_rejected(self):
        value = self.store.create(self.ACCOUNT)
        target = self.home / "other"
        self.path.rename(target)
        self.path.symlink_to(target)
        for operation in (self.store.get, self.store.delete):
            with self.subTest(operation=operation.__name__), self.assertRaises(OSError):
                operation(self.ACCOUNT)
        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            self.store.create(self.ACCOUNT)
        self.path.unlink()
        self.path.hardlink_to(target)
        for operation in (self.store.get, self.store.delete):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(RuntimeError, "single-link"):
                    operation(self.ACCOUNT)
        self.assertEqual(target.read_text(), value + "\n")

    def test_non_regular_or_corrupt_file_is_rejected(self):
        self.store.create(self.ACCOUNT)
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        with self.assertRaisesRegex(RuntimeError, "regular"):
            self.store.get(self.ACCOUNT)
        self.path.unlink()
        for value in ("", "truncated", "B9!" + "x" * 38 + "\nextra"):
            with self.subTest(value=value):
                self.path.touch(mode=0o600)
                self.path.write_text(value)
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    self.store.get(self.ACCOUNT)

    def test_failed_flush_or_round_trip_is_not_reported_as_success(self):
        with self.store.directory(create=True):
            pass
        with patch("infra.os.fsync", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(OSError, "disk failure"):
                self.store.create(self.ACCOUNT)
        self.path.unlink()
        with patch.object(self.store, "read", return_value="different"):
            with self.assertRaisesRegex(RuntimeError, "round-trip"):
                self.store.create(self.ACCOUNT)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        subscription = patch("infra.SUBSCRIPTION", "00000000-0000-0000-0000-000000000001")
        subscription.start()
        self.addCleanup(subscription.stop)

    def config(self, directory):
        return {"results": str(directory), "run_id": "1234abcd", "subscription": infra.SUBSCRIPTION,
                "group": "rg-horizon-bench-1234abcd", "password": "secret",
                "client_vms": ["vm1", "vm2"]}

    def state(self):
        return {"run_id": "1234abcd", "subscription": infra.SUBSCRIPTION,
                "group": "rg-horizon-bench-1234abcd", "format": FORMAT,
                "credential_account": infra.SUBSCRIPTION + "/1234abcd", "benchmark": __file__,
                "expires_utc": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=16)).isoformat(),
                "phase": "paused"}

    def test_invalid_subscription_is_rejected_before_any_side_effects(self):
        for value in ("", "not-a-subscription", "0" * 32,
                      "urn:uuid:00000000-0000-0000-0000-000000000001"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                results = Path(directory) / "results"
                with (patch("infra.SUBSCRIPTION", value), patch("infra.RESULTS", results),
                      patch("sys.argv", ["infra.py", __file__]),
                      patch("infra.az") as azure, patch("infra.Credentials") as credentials,
                      patch("infra.secrets.token_hex") as run_id,
                      patch("sys.stderr", io.StringIO()) as errors):
                    with self.assertRaises(SystemExit) as exited:
                        infra.main()
                self.assertEqual(exited.exception.code, 2)
                self.assertIn("AZURE_SUBSCRIPTION_ID", errors.getvalue())
                self.assertFalse(results.exists())
                azure.assert_not_called()
                credentials.assert_not_called()
                run_id.assert_not_called()

    def test_subscription_is_read_from_environment_without_cloud_access(self):
        environment = dict(os.environ, AZURE_SUBSCRIPTION_ID=infra.SUBSCRIPTION)
        result = subprocess.run(
            [sys.executable, "-c", "import infra; print(infra.SUBSCRIPTION)"],
            env=environment, text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), infra.SUBSCRIPTION)

    def test_linux_run_pins_file_store_for_resume_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            with (patch("infra.RESULTS", results), patch("infra.Path.home", return_value=Path(directory)),
                  patch("infra.sys.platform", "linux"), patch("infra.REDACTIONS", []),
                  patch("infra.secrets.token_hex", return_value="1234abcd"),
                  patch("infra.ctypes.CDLL") as api, patch("infra.az") as azure,
                  patch("infra.execute") as execute):
                with patch("sys.argv", ["infra.py", __file__]):
                    infra.main()
                state, password, _ = execute.call_args.args
                self.assertEqual(state["credential_store"], "file")
                state_path = results / state["run_id"] / "state.json"
                self.assertNotIn(password, state_path.read_text())
                credential = infra.FileCredentials()
                self.assertEqual(credential.get(state["credential_account"]), password)
                azure.assert_not_called()
                azure.side_effect = [True, {"tags": {"BenchmarkRun": state["run_id"]}}]
                with (patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                      patch("infra.sys.platform", "darwin")):
                    infra.main()
                self.assertEqual(execute.call_count, 2)
                self.assertEqual(execute.call_args.args[1], password)
                with (patch("sys.argv", ["infra.py", "--cleanup", state["run_id"]]),
                      patch("infra.cleanup") as cleanup):
                    infra.main()
                cleanup.assert_called_once_with(state["group"], state["run_id"])
                with self.assertRaisesRegex(RuntimeError, "missing"):
                    credential.get(state["credential_account"])
                saved = json.loads(state_path.read_text())
                self.assertEqual(saved["phase"], "deleted")
                self.assertTrue(saved["credential_removed"])
                api.assert_not_called()

    def test_new_run_can_explicitly_choose_file_store_on_macos(self):
        with tempfile.TemporaryDirectory() as directory:
            with (patch("infra.RESULTS", Path(directory) / "results"),
                  patch("infra.Path.home", return_value=Path(directory)),
                  patch("infra.sys.platform", "darwin"), patch("infra.REDACTIONS", []),
                  patch("sys.argv", ["infra.py", __file__, "--credential-store", "file"]),
                  patch("infra.execute") as execute, patch("infra.ctypes.CDLL") as api):
                infra.main()
                state, password, _ = execute.call_args.args
                self.assertEqual(state["credential_store"], "file")
                self.assertEqual(infra.Credentials("file").get(state["credential_account"]), password)
                api.assert_not_called()

    def test_new_macos_run_pins_keychain_store(self):
        with tempfile.TemporaryDirectory() as directory:
            with (patch("infra.RESULTS", Path(directory) / "results"),
                  patch("infra.sys.platform", "darwin"), patch("infra.REDACTIONS", []),
                  patch("sys.argv", ["infra.py", __file__]),
                  patch("infra.execute") as execute, patch("infra.KeychainCredentials") as keychain):
                keychain.return_value.create.return_value = "secret"
                infra.main()
                state, password, _ = execute.call_args.args
                self.assertEqual(state["credential_store"], "keychain")
                self.assertEqual(password, "secret")
                keychain.return_value.create.assert_called_once_with(state["credential_account"])

    def test_legacy_keychain_run_does_not_fall_back_to_file_on_linux(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            atomic_json(Path(directory) / state["run_id"] / "state.json", state)
            with (patch("infra.RESULTS", Path(directory)), patch("infra.sys.platform", "linux"),
                  patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                  patch("infra.az", side_effect=[True, {"tags": {"BenchmarkRun": state["run_id"]}}]),
                  patch("infra.FileCredentials") as files, patch("infra.execute") as execute):
                with self.assertRaisesRegex(RuntimeError, "original Mac"):
                    infra.main()
                files.assert_not_called()
                execute.assert_not_called()

    def test_unknown_saved_store_fails_before_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            state["credential_store"] = "unsupported"
            atomic_json(Path(directory) / state["run_id"] / "state.json", state)
            with (patch("infra.RESULTS", Path(directory)),
                  patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                  patch("infra.az") as azure, patch("infra.Credentials") as credentials):
                with self.assertRaisesRegex(RuntimeError, "Unknown saved credential store"):
                    infra.main()
                azure.assert_not_called()
                credentials.assert_not_called()

    def test_retained_run_store_cannot_be_overridden(self):
        for action in ("--resume", "--cleanup"):
            with (self.subTest(action=action),
                  patch("sys.argv", ["infra.py", action, "1234abcd", "--credential-store", "file"]),
                  patch("sys.stderr", io.StringIO()), patch("infra.az") as azure,
                  patch("infra.Credentials") as credentials):
                with self.assertRaises(SystemExit) as exited:
                    infra.main()
                self.assertEqual(exited.exception.code, 2)
                azure.assert_not_called()
                credentials.assert_not_called()

    def test_credential_write_failure_prevents_cloud_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            credential_directory = home / ".horizon-bench-credentials"
            credential_directory.mkdir(mode=0o755)
            credential_directory.chmod(0o755)
            with (patch("infra.RESULTS", home / "results"),
                  patch("infra.Path.home", return_value=home),
                  patch("sys.argv", ["infra.py", __file__, "--credential-store", "file"]),
                  patch("infra.az") as azure, patch("infra.execute") as execute):
                with self.assertRaisesRegex(RuntimeError, "mode 0700"):
                    infra.main()
                azure.assert_not_called()
                execute.assert_not_called()

    def test_atomic_write_and_controller_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            atomic_json(path, {"phase": "paused"})
            self.assertEqual(json.loads(path.read_text()), {"phase": "paused"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with run_lock(directory):
                with self.assertRaisesRegex(RuntimeError, "Another controller"):
                    with run_lock(directory):
                        self.fail("Two controllers acquired the same run")
            with run_lock(directory):
                pass

    def test_failed_atomic_replace_keeps_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            atomic_json(path, {"phase": "old"})
            with patch("durable.os.replace", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    atomic_json(path, {"phase": "new"})
            self.assertEqual(json.loads(path.read_text()), {"phase": "old"})
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_corrupt_and_legacy_checkpoints_are_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "progress.json"
            path.write_text('{"operations":')
            with self.assertRaises(json.JSONDecodeError):
                Journal(path, {})
            atomic_json(path, {"format": 1, "identity": {}, "operations": {}})
            with self.assertRaisesRegex(RuntimeError, "version"):
                Journal(path, {})

    def test_partial_provisioning_reconciles_accepted_resource_without_recreate(self):
        state = self.state()
        state["resources"] = {"db": "creating"}
        for data in ({"state": "Ready"}, {"properties": {"provisioningState": "Succeeded"}}):
            with self.subTest(data=data), patch("infra.save_state"), patch("infra.az", side_effect=[
                [{"name": "db", "type": "Microsoft.HorizonDb/clusters"}], data,
            ]) as azure:
                validate = MagicMock()
                infra.ensure_resource(state, "Microsoft.HorizonDb/clusters", "db",
                                      ("create",), ("show",), validate)
                validate.assert_called_once_with(data)
                self.assertFalse(any(c.args == ("create",) for c in azure.call_args_list))
                self.assertEqual(state["resources"]["db"], "ready")

    def test_missing_completed_resource_is_not_recreated(self):
        state = self.state()
        state["resources"] = {"db": "ready"}
        with patch("infra.save_state"), patch("infra.az", return_value=[]) as azure:
            with self.assertRaisesRegex(RuntimeError, "refusing to recreate"):
                infra.ensure_resource(state, "type", "db", ("create",), ("show",), lambda _: None)
            azure.assert_called_once()

    def test_interruptions_pause_without_deleting_or_discarding_credentials(self):
        for error in (KeyboardInterrupt(), TimeoutError("deadline"), SystemExit("signal"),
                      RuntimeError("external stop")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                state = self.state()
                args = SimpleNamespace(resume=state["run_id"], start_clients=False)
                with (patch("infra.RESULTS", Path(directory)), patch("infra.provision", side_effect=error),
                      patch("infra.pause_clients") as pause, patch("infra.cleanup") as cleanup,
                      patch("infra.Credentials") as credentials, patch("sys.stderr", io.StringIO())):
                    with self.assertRaises(type(error)):
                        infra.execute(state, "secret", args)
                pause.assert_called_once()
                cleanup.assert_not_called()
                credentials.assert_not_called()
                self.assertEqual(state["phase"], "paused")
                self.assertEqual(state["credential_account"], infra.SUBSCRIPTION + "/1234abcd")

    def test_cleanup_removes_credential_only_after_verified_group_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            events = []
            with (patch("infra.RESULTS", Path(directory)),
                  patch("infra.cleanup", side_effect=lambda *_: events.append("deleted")),
                  patch("infra.Credentials") as credentials):
                credentials.return_value.delete.side_effect = lambda _: events.append("credential")
                infra.finish_cleanup(state)
            self.assertEqual(events, ["deleted", "credential"])
            credentials.assert_called_once_with("keychain")
            self.assertEqual(state["phase"], "deleted")
            with (patch("infra.RESULTS", Path(directory)),
                  patch("infra.cleanup", side_effect=RuntimeError("not deleted")),
                  patch("infra.Credentials") as credentials):
                with self.assertRaises(RuntimeError):
                    infra.finish_cleanup(state)
                credentials.assert_not_called()

    def test_completed_resume_cleans_up_without_starting_clients_or_renewing_window(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            state["expires_utc"] = "2000-01-01T00:00:00+00:00"
            folder = Path(directory) / state["run_id"]
            atomic_json(folder / "state.json", state)
            atomic_json(folder / "manifest.json", {"format": FORMAT, "status": "completed"})
            with (patch("infra.RESULTS", Path(directory)),
                  patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                  patch("infra.az", side_effect=[True, {"tags": {"BenchmarkRun": state["run_id"]}}]),
                  patch("infra.finish_cleanup") as cleanup, patch("infra.provision") as provision):
                infra.main()
                cleanup.assert_called_once()
                provision.assert_not_called()

    def test_successful_controller_exit_and_durable_manifest_allow_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            process = MagicMock()
            process.poll.return_value = 0

            def completed(**kwargs):
                atomic_json(Path(directory) / state["run_id"] / "manifest.json",
                            {"format": FORMAT, "status": "completed"})
                return 0

            process.wait.side_effect = completed
            with (patch("infra.RESULTS", Path(directory)), patch("infra.provision", return_value={}),
                  patch("infra.DEADLINE", time.monotonic() + 3600),
                  patch("infra.subprocess.Popen", return_value=process), patch("infra.cleanup") as cleanup,
                  patch("infra.pause_clients") as pause, patch("infra.Credentials") as credentials):
                infra.execute(state, "secret", SimpleNamespace(resume=state["run_id"], start_clients=False))
                cleanup.assert_called_once_with(state["group"], state["run_id"])
                credentials.return_value.delete.assert_called_once_with(state["credential_account"])
                pause.assert_not_called()
            self.assertEqual(state["phase"], "deleted")
            self.assertEqual(state["outcome"], "completed")

    def test_stopped_clients_require_explicit_start_and_are_started_only_once(self):
        state = self.state()
        state["transport_verified"] = True
        with (patch("infra.ensure_resource"), patch("infra.subprocess.run"),
              patch("infra.client_power", return_value="PowerState/deallocated"),
              patch("infra.az") as azure):
            with self.assertRaisesRegex(RuntimeError, "--start-clients"):
                infra.provision(state, "secret")
            azure.assert_not_called()
        with (patch("infra.ensure_resource"), patch("infra.subprocess.run"),
              patch("infra.client_power", side_effect=[
                  "PowerState/deallocated", "PowerState/running",
                  "PowerState/deallocated", "PowerState/running",
              ]), patch("infra.az", return_value={"publicIps": "192.0.2.1"}) as azure,
              patch("infra.install_watchdog"), patch("infra.DEADLINE", time.monotonic() + 3600)):
            infra.provision(state, "secret", start_clients=True)
            self.assertEqual(sum(c.args[:2] == ("vm", "start") for c in azure.call_args_list), 2)

    def test_resume_refuses_deleted_foreign_and_missing_groups(self):
        for phase, exists, tags in (
            ("deleted", True, {"BenchmarkRun": "1234abcd"}),
            ("paused", False, {}),
            ("paused", True, {"BenchmarkRun": "other"}),
        ):
            with self.subTest(phase=phase, exists=exists, tags=tags), tempfile.TemporaryDirectory() as directory:
                state = self.state()
                state["phase"] = phase
                folder = Path(directory) / state["run_id"]
                atomic_json(folder / "state.json", state)
                with (patch("infra.RESULTS", Path(directory)),
                      patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                      patch("infra.az", side_effect=[exists, {"tags": tags}]) as azure,
                      patch("infra.Credentials") as credentials):
                    with self.assertRaises(RuntimeError):
                        infra.main()
                    credentials.assert_not_called()
                    self.assertFalse(any(c.args[:2] == ("group", "create") for c in azure.call_args_list))

    def test_expired_window_requires_explicit_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state()
            state["expires_utc"] = "2000-01-01T00:00:00+00:00"
            atomic_json(Path(directory) / state["run_id"] / "state.json", state)
            with (patch("infra.RESULTS", Path(directory)),
                  patch("sys.argv", ["infra.py", "--resume", state["run_id"]]),
                  patch("infra.az", side_effect=[True, {"tags": {"BenchmarkRun": state["run_id"]}}]),
                  patch("infra.Credentials") as credentials, patch("infra.execute") as execute):
                with self.assertRaisesRegex(RuntimeError, "window expired"):
                    infra.main()
                credentials.assert_not_called()
                execute.assert_not_called()
            with (patch("infra.RESULTS", Path(directory)),
                  patch("sys.argv", ["infra.py", "--resume", state["run_id"], "--extend-hours", "8"]),
                  patch("infra.az", side_effect=[True, {"tags": {"BenchmarkRun": state["run_id"]}}, {}]),
                  patch("infra.Credentials") as credentials, patch("infra.execute") as execute):
                infra.main()
                self.assertEqual(execute.call_count, 1)
                credentials.assert_called_once_with("keychain")
                saved = json.loads((Path(directory) / state["run_id"] / "state.json").read_text())
                self.assertGreater(dt.datetime.fromisoformat(saved["expires_utc"]), dt.datetime.now(dt.timezone.utc))

    def test_command_interruption_keeps_running_command(self):
        remote = bench.Remote(self.config("."))
        with patch("infra.az", side_effect=[None, KeyboardInterrupt()]) as azure:
            with self.assertRaises(KeyboardInterrupt):
                remote.script("vm1", "work", 10)
            self.assertFalse(any(c.args[:3] == ("vm", "run-command", "delete") for c in azure.call_args_list))

    def test_generated_setup_and_watchdog_scripts_preserve_shell_and_pause_permissions(self):
        remote = bench.Remote(self.config("."))
        captured = []
        with (patch.object(remote, "sweep_commands"), patch.object(remote, "save"),
              patch.object(remote, "script", side_effect=lambda vm, source, *a, **k: (
                  captured.append(source) or {"exitCode": 0, "output": "BENCH_SETUP_OK"}
              ))):
            remote.setup("vm1")
        self.assertTrue(captured[0].startswith("#!/bin/bash\n"))
        self.assertIn("flock -n 9", captured[0])
        roles = []

        def azure(*args, **kwargs):
            if args[:2] == ("vm", "show"):
                return {"identity": {"principalId": "principal"}}
            if args[:3] == ("role", "assignment", "create"):
                roles.append((args[args.index("--role") + 1], args[args.index("--scope") + 1]))
                return None
            captured.append(args[args.index("--scripts") + 1])
            return {"value": [{"message": "WATCHDOG_ACCESS_OK\nactive\n"}]}

        with patch("infra.az", side_effect=azure):
            infra.install_watchdog("rg-horizon-bench-1234abcd", "1234abcd", "2099-01-01 00:00:00 UTC")
        self.assertEqual([role for role, _ in roles],
                         ["Reader", "Virtual Machine Contributor", "Virtual Machine Contributor"])
        self.assertTrue(all("/virtualMachines/" in scope for _, scope in roles[1:]))
        for source in captured:
            result = subprocess.run(["bash", "-n"], input=source, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Persistent=true", captured[1])
        self.assertNotIn("benchmark-cleanup", captured[1])

    def test_existing_command_is_attached_not_submitted_again(self):
        remote = bench.Remote(self.config("."))
        terminal = {"properties": {"instanceView": {"executionState": "Succeeded", "exitCode": 0}}}
        with patch("infra.az", side_effect=[[{"name": "bench-work-id"}], terminal, None]) as azure:
            remote.script("vm1", "work", 10, name="bench-work-id")
            self.assertFalse(any(c.args[:3] == ("rest", "--method", "put") for c in azure.call_args_list))
            self.assertEqual(azure.call_args.args[:3], ("vm", "run-command", "delete"))

    def test_vm_artifact_is_recovered_when_original_command_is_gone(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            record, _ = remote.prepare_job("measure/1", "vm1", "measure", "host", {"users": 1})
            view = artifact_view(record["job"], {"nopm": 123})
            with patch.object(remote, "commands", return_value=[]), patch.object(remote, "script", return_value=view) as script:
                result = remote.job("vm1", "measure", "host", key="measure/1", users=1)
                self.assertEqual(result["nopm"], 123)
                self.assertIn("--inspect", script.call_args.args[1])
                self.assertEqual(script.call_count, 1)
            self.assertEqual(record["status"], "completed")

    def test_busy_worker_blocks_duplicate_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            remote.prepare_job("build", "vm1", "build", "host", {})
            with (patch.object(remote, "commands", return_value=[]),
                  patch.object(remote, "script", return_value={"exitCode": 75, "output": 'BENCH_STATUS:{"state":"busy"}'}) as script):
                with self.assertRaisesRegex(RuntimeError, "live worker"):
                    remote.job("vm1", "build", "host", key="build")
                self.assertEqual(script.call_count, 1)
                self.assertIn("--inspect", script.call_args.args[1])

    def test_recovered_failure_retries_with_new_identity_in_same_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            old, _ = remote.prepare_job("measure", "vm1", "measure", "host", {})
            executed = []

            def script(vm, source, timeout, protected, **kwargs):
                job = json.loads(protected["JOB"])
                if "--inspect" in source:
                    return artifact_view(job, ok=False)
                executed.append(job["job_id"])
                view = artifact_view(job, {"nopm": 5})
                kwargs["on_terminal"](view)
                return view

            with (patch.object(remote, "commands", return_value=[]),
                  patch.object(remote, "script", side_effect=script),
                  patch("sys.stdout", io.StringIO())):
                remote.recover_pending()
                self.assertEqual(old["status"], "failed")
                self.assertEqual(remote.job("vm1", "measure", "host", key="measure"), {"nopm": 5})
            self.assertEqual(len(executed), 1)
            self.assertNotEqual(executed[0], old["job"]["job_id"])

    def test_result_saved_before_progress_commit_is_not_executed_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))

            def script(vm, source, timeout, protected, **kwargs):
                view = artifact_view(json.loads(protected["JOB"]), {"nopm": 123})
                kwargs["on_terminal"](view)
                return view

            with (patch.object(remote, "script", side_effect=script),
                  patch.object(remote, "finish_job", side_effect=KeyboardInterrupt()),
                  patch("sys.stdout", io.StringIO())):
                with self.assertRaises(KeyboardInterrupt):
                    remote.job("vm1", "measure", "host", key="measure/1", users=1)
            resumed = bench.Remote(self.config(directory))
            with patch.object(resumed, "script") as script, patch.object(resumed, "commands") as commands:
                self.assertEqual(resumed.job("vm1", "measure", "host", key="measure/1", users=1), {"nopm": 123})
                script.assert_not_called()
                commands.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, "Inputs changed"):
                resumed.job("vm1", "measure", "host", key="measure/1", users=2)
            record = resumed.journal.data["operations"]["measure/1"]
            path = Path(directory) / f"measure-{record['job']['job_id']}.json"
            value = json.loads(path.read_text())
            value["result"]["nopm"] = 999
            atomic_json(path, value)
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                resumed.job("vm1", "measure", "host", key="measure/1", users=1)

    def test_completed_view_survives_interruption_before_command_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            record, _ = remote.prepare_job("measure", "vm1", "measure", "host", {})
            record["view"] = artifact_view(record["job"], {"nopm": 5})
            remote.journal.save()
            with (patch.object(remote, "commands", return_value=[{"name": "bench-work-" + record["job"]["job_id"]}]),
                  patch.object(remote, "delete_command") as delete, patch.object(remote, "script") as script,
                  patch("sys.stdout", io.StringIO())):
                self.assertEqual(remote.job("vm1", "measure", "host", key="measure"), {"nopm": 5})
                delete.assert_called_once()
                script.assert_not_called()

    def test_failed_command_cannot_be_hidden_by_success_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))

            def script(vm, source, timeout, protected, **kwargs):
                view = artifact_view(json.loads(protected["JOB"]), {"nopm": 5})
                view["exitCode"] = 1
                return view

            with patch.object(remote, "script", side_effect=script):
                with self.assertRaisesRegex(RuntimeError, "success-shaped"):
                    remote.job("vm1", "measure", "host", key="measure")

    def test_distributed_pair_retries_both_halves_not_one_old_and_one_new(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            target = {"host": "host"}
            remote.journal.data["pairs"]["pair"] = {"attempt": 0, "start_at": 1}
            calls = []

            def job(vm, operation, host, *, key, recover_only=False, **parameters):
                calls.append((vm, key, recover_only, parameters["start_at"]))
                if recover_only:
                    return {"started_epoch": 1} if vm == "vm1" else None
                return {"started_epoch": parameters["start_at"]}

            with patch.object(remote, "job", side_effect=job):
                results = remote.distributed("pair", target, 50, "dataset", 8)
            self.assertEqual(remote.journal.data["pairs"]["pair"]["attempt"], 1)
            launched = [call for call in calls if not call[2]]
            self.assertEqual(len(launched), 2)
            self.assertTrue(all("/1/" in call[1] for call in launched))
            self.assertEqual(results[0]["started_epoch"], results[1]["started_epoch"])
            self.assertGreater(results[0]["started_epoch"], 1)

    def test_distributed_busy_or_invalid_skew_never_mixes_results(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = bench.Remote(self.config(directory))
            target = {"host": "host"}
            remote.journal.data["pairs"]["pair"] = {"attempt": 0, "start_at": 1}
            with patch.object(remote, "job", side_effect=RuntimeError("busy")):
                with self.assertRaisesRegex(RuntimeError, "busy"):
                    remote.distributed("pair", target, 50, "dataset", 8)
                self.assertEqual(remote.journal.data["pairs"]["pair"]["attempt"], 0)
            with patch.object(remote, "job", side_effect=lambda vm, *a, **k: {
                "started_epoch": 1 if vm == "vm1" else 4,
            }):
                with self.assertRaisesRegex(RuntimeError, "over two seconds"):
                    remote.distributed("pair", target, 50, "dataset", 8)
            self.assertEqual(remote.journal.data["pairs"]["pair"]["status"], "invalid_start_skew")
            with patch.object(remote, "job", side_effect=lambda *a, **k: {"started_epoch": k["start_at"]}) as job:
                remote.distributed("pair", target, 50, "dataset", 8)
                self.assertEqual(job.call_count, 2)
                self.assertEqual(remote.journal.data["pairs"]["pair"]["attempt"], 1)

    def test_worker_replays_completed_job_and_recovers_stale_started_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            job = {"job_id": "1234567890abcdef", "format": FORMAT, "operation": "metadata"}
            atomic_json(Path(directory) / f"{job['job_id']}.started.json", job)
            with (patch("worker.ROOT", Path(directory)),
                  patch.dict(os.environ, JOB=json.dumps(job), DB_PASSWORD="secret"),
                  patch("sys.argv", ["worker.py"]), patch("sys.stdout", io.StringIO()),
                  patch("worker.metadata", return_value={"version": 17}) as metadata):
                worker.main()
                worker.main()
                self.assertEqual(metadata.call_count, 1)

    def test_orphaned_child_keeps_worker_lock_after_parent_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = (
                "import fcntl,os,subprocess,sys\n"
                "f=open(sys.argv[1],'a')\nfcntl.flock(f,fcntl.LOCK_EX)\n"
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
                "pass_fds=(f.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "print(p.pid,flush=True)\nos._exit(0)\n"
            )
            process = subprocess.run([sys.executable, "-c", source, str(Path(directory) / "worker.lock")],
                                     capture_output=True, text=True, check=True, timeout=10)
            child = int(process.stdout)
            job = {"job_id": "1234567890abcdef", "format": FORMAT}
            try:
                with (patch("worker.ROOT", Path(directory)),
                      patch.dict(os.environ, JOB=json.dumps(job)),
                      patch("sys.argv", ["worker.py", "--inspect"]), patch("sys.stdout", io.StringIO()) as output):
                    with self.assertRaises(SystemExit) as stopped:
                        worker.main()
                    self.assertEqual(stopped.exception.code, 75)
                    self.assertIn('"busy"', output.getvalue())
            finally:
                os.kill(child, signal.SIGTERM)
            with (Path(directory) / "worker.lock").open("a") as lock:
                for _ in range(100):
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(.01)
                else:
                    self.fail("Orphan lock was not released after the child exited")

    def test_completed_dataset_survives_missing_worker_artifact(self):
        job = {"run_id": "1234abcd", "dataset_id": "dataset", "warehouses": 50, "host": "host"}
        result = {"database": {"sizes": {"warehouses": 50}}, "log": "SCHEMA COMPLETE"}
        marker = {**job, "result": result}
        with (patch("worker.dataset_marker", return_value=(marker, True)),
              patch("worker.validate_dataset") as validate, patch("worker.run_hammer") as hammer,
              patch("worker.connect") as connect):
            self.assertEqual(worker.build(job), result)
            hammer.assert_not_called()
            connect.assert_not_called()
            validate.assert_called_once_with(job)

    def test_unmarked_foreign_database_and_wrong_dataset_are_rejected(self):
        job = {"run_id": "1234abcd", "dataset_id": "dataset", "warehouses": 50, "host": "host"}
        with tempfile.TemporaryDirectory() as directory, patch("worker.ROOT", Path(directory)):
            with patch("worker.dataset_marker", return_value=(None, True)), patch("worker.connect") as connect:
                with self.assertRaisesRegex(RuntimeError, "unmarked"):
                    worker.build(job)
                connect.assert_not_called()
            with patch("worker.dataset_marker", return_value=({**job, "dataset_id": "foreign"}, True)):
                with self.assertRaisesRegex(RuntimeError, "unexpected identity"):
                    worker.build(job)
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    worker.validate_dataset(job)

    def test_only_unfinished_owned_build_is_rebuilt(self):
        job = {"run_id": "1234abcd", "dataset_id": "dataset", "warehouses": 50, "host": "host"}
        with tempfile.TemporaryDirectory() as directory:
            intent = Path(directory) / ("build-" + hashlib.sha256(b"host").hexdigest()[:16] + ".json")
            atomic_json(intent, job)
            connection = MagicMock()
            with (patch("worker.ROOT", Path(directory)),
                  patch("worker.dataset_marker", return_value=(None, True)),
                  patch("worker.connect", return_value=connection),
                  patch("worker.run_hammer", return_value={"log": "SCHEMA COMPLETE"}),
                  patch("worker.database_state", return_value={"sizes": {"warehouses": 50}})):
                worker.build(job)
            statements = [c.args[0] for c in connection.cursor.return_value.__enter__.return_value.execute.call_args_list]
            self.assertEqual(sum("DROP DATABASE" in sql for sql in statements), 1)
            connection.commit.assert_called_once()
            self.assertTrue(any("INSERT INTO bench_control.dataset" in sql for sql in statements))

    def test_watchdog_never_deletes_and_pauses_second_client_first(self):
        state = self.state()
        state["expires_utc"] = "2000-01-01T00:00:00+00:00"
        mutations = []

        def request(url, **kwargs):
            if "oauth2/token" in url:
                return {"access_token": "test"}
            if kwargs.get("method"):
                mutations.append((url, kwargs["method"]))
                return None
            if "/instanceView?" in url:
                return {"statuses": [{"code": "PowerState/deallocated"}]}
            if "/virtualMachines/" in url:
                return {"tags": {"BenchmarkRun": state["run_id"]}}
            return {"tags": {"BenchmarkRun": state["run_id"], "ExpiresUTC": state["expires_utc"]}}

        with (patch("sys.argv", ["watchdog.py", infra.SUBSCRIPTION, state["group"], state["run_id"]]),
              patch("watchdog.request", side_effect=request), patch("sys.stdout", io.StringIO())):
            watchdog.main()
        self.assertEqual([method for _, method in mutations], ["POST", "POST"])
        self.assertIn("bench-client-2/deallocate", mutations[0][0])
        self.assertIn("bench-client-1/deallocate", mutations[1][0])
        mutations.clear()
        state["expires_utc"] = "2099-01-01T00:00:00+00:00"
        with (patch("sys.argv", ["watchdog.py", infra.SUBSCRIPTION, state["group"], state["run_id"]]),
              patch("watchdog.request", side_effect=request), patch("sys.stdout", io.StringIO())):
            watchdog.main()
        self.assertEqual(mutations, [])


class MetricsTests(unittest.TestCase):
    def definition(self, name, *grains):
        return {"name": {"value": name}, "metricAvailabilities": [
            {"timeGrain": grain, "retention": "P93D"} for grain in grains
        ]}

    def test_export_uses_the_finest_common_supported_interval(self):
        for grains, expected in (
            (("PT1M", "PT30M"), "PT1M"),
            (("PT30M", "PT1H"), "PT30M"),
        ):
            with self.subTest(expected=expected):
                definitions = [
                    self.definition("cpu_percent", "PT1M", "PT30M", "PT1H"),
                    self.definition("memory_percent", *grains),
                ]
                remote = MagicMock()
                with patch("infra.az", side_effect=[definitions, {"interval": expected}]) as azure:
                    bench.capture_metrics(remote, {"db": {"id": "test-resource"}}, "2026-01-01T00:00:00Z")
                args = azure.call_args.args
                self.assertEqual(args[args.index("--interval") + 1], expected)
                self.assertEqual(remote.save.call_args.args, ("metrics-db-0", {"interval": expected}))

    def test_export_checks_each_batch_independently(self):
        definitions = [self.definition(f"cpu_metric_{n}", "PT30M") for n in range(10)]
        definitions.extend(self.definition(f"memory_metric_{n}", "PT1M") for n in range(2))
        with patch("infra.az", side_effect=[definitions, {}, {}]) as azure:
            bench.capture_metrics(MagicMock(), {"db": {"id": "test-resource"}}, "2026-01-01T00:00:00Z")
        intervals = [
            call.args[call.args.index("--interval") + 1]
            for call in azure.call_args_list[1:]
        ]
        self.assertEqual(intervals, ["PT30M", "PT1M"])

    def test_export_rejects_metrics_without_a_supported_common_interval(self):
        definitions = [
            self.definition("cpu_percent", "PT1M"),
            self.definition("memory_percent", "PT30M"),
        ]
        with patch("infra.az", return_value=definitions) as azure:
            with self.assertRaisesRegex(RuntimeError, "common metrics interval"):
                bench.capture_metrics(MagicMock(), {"db": {"id": "test-resource"}}, "2026-01-01T00:00:00Z")
        azure.assert_called_once()


class OrchestrationTests(unittest.TestCase):
    def test_resume_after_partial_build_and_result_save_skips_completed_stages(self):
        for failure in ("partial_build", "saved_measurement"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                config = ResumeTests().config(directory)
                config.update(horizon="hd", flexible="fs", flexible_replica="replica",
                              deadline_epoch=time.time() + 1000000)
                datasets, artifacts, executions = {}, {}, {}
                interrupted = False

                class FakeRemote(bench.Remote):
                    def setup(self, vm):
                        pass

                    def commands(self, vm):
                        return []

                    def script(self, vm, source, timeout, protected, **kwargs):
                        nonlocal interrupted
                        job = json.loads(protected["JOB"])
                        job_id = job["job_id"]
                        if "--inspect" in source:
                            return artifacts.get(job_id, {"exitCode": 0, "output": 'BENCH_STATUS:{"state":"interrupted"}'})
                        operation, host = job["operation"], job["host"]
                        if (failure == "partial_build" and not interrupted and operation == "build"
                                and host == "fs.host" and job["warehouses"] == 50):
                            interrupted = True
                            raise KeyboardInterrupt()
                        executions[job_id] = executions.get(job_id, 0) + 1
                        if operation == "metadata":
                            result = {"settings": [{"name": k, "setting": v} for k, v in {
                                "max_connections": "1000", "synchronous_commit": "on", "fsync": "on",
                            }.items()]}
                        elif operation == "build":
                            datasets[host] = job["dataset_id"]
                            result = {"database": {"sizes": {"warehouses": job["warehouses"],
                                                            "data_bytes": job["warehouses"] * 2**30}},
                                      "started_epoch": 1, "ended_epoch": 2}
                        elif operation in ("measure", "validate", "supplement"):
                            if datasets[host] != job["dataset_id"]:
                                raise RuntimeError("Wrong live dataset")
                            sizes = {"sizes": {"data_bytes": job["warehouses"] * 2**30}}
                            result = {"nopm": job.get("users", 1), "tpm": 123,
                                      "before": sizes, "after": sizes, "telemetry": {"cpu_p95_percent": 10},
                                      "started_epoch": job.get("start_at", 1)}
                        else:
                            result = {"visibility_seconds": .1}
                        view = artifact_view(job, result)
                        artifacts[job_id] = view
                        if kwargs.get("on_terminal"):
                            kwargs["on_terminal"](view)
                        return view

                    def save(self, name, data):
                        nonlocal interrupted
                        super().save(name, data)
                        if (failure == "saved_measurement" and not interrupted and name.startswith("measure-")
                                and data["job"].get("warehouses") == 250 and data["job"]["host"] == "hd.host"):
                            interrupted = True
                            raise KeyboardInterrupt()

                def azure(*args, **kwargs):
                    if args[:2] == ("horizondb", "show"):
                        return {"id": "hd", "properties": {"vCores": 8, "replicaCount": 2,
                                "fullyQualifiedDomainName": "hd.host.horizondb.azure.com",
                                "readonlyEndpoint": "ro.host.horizondb.azure.com"}}
                    if args[:3] == ("postgres", "flexible-server", "show"):
                        name = args[args.index("-n") + 1]
                        return {"id": name, "sku": {"name": "Standard_E8ds_v5"},
                                "fullyQualifiedDomainName": name + ".host"}
                    return []

                def endpoint_override(_):
                    return {"primary": "hd.host", "reader": "ro.host"}

                with (patch.dict(os.environ, BENCH_CONFIG=json.dumps(config)),
                      patch("run_benchmark.Remote", FakeRemote), patch("run_benchmark.USERS", (1,)),
                      patch("run_benchmark.endpoints", side_effect=endpoint_override),
                      patch("infra.az", side_effect=azure), patch("sys.stdout", io.StringIO())):
                    with self.assertRaises(KeyboardInterrupt):
                        bench.main()
                    bench.main()
                    # A completed rerun must not rebuild even the last database.
                    bench.main()
                manifest = json.loads((Path(directory) / "manifest.json").read_text())
                self.assertEqual(manifest["status"], "completed")
                self.assertTrue(all(stage["status"] == "completed" for stage in manifest["stages"]))
                self.assertTrue(all(count == 1 for count in executions.values()))
                jobs = [bench.decode_result(view["output"].split("BENCH_DATA:")[1])
                        for view in artifacts.values()]
                builds = [value["job"] for value in jobs if value["job"]["operation"] == "build"]
                self.assertEqual(len(builds), 8)  # Calibration and three stages on two services.
                csv_rows = (Path(directory) / "tprocc.csv").read_text().splitlines()
                self.assertEqual(len(csv_rows), 31)  # 2*(3 + 3 + 9), plus header.
                identities = [(r["service"], r["target_gib"], r["active_users"], r["repeat"])
                              for stage in manifest["stages"] for r in stage["rows"]]
                self.assertEqual(len(identities), len(set(identities)))
                self.assertNotIn(config["password"], (Path(directory) / "progress.json").read_text())


if __name__ == "__main__":
    unittest.main()
