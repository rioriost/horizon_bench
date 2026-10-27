import base64
import hashlib
import json
from pathlib import Path
import io
import os
import random
import re
import resource
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

import infra
import run_benchmark
import worker


class AzureReadRetryTests(unittest.TestCase):
    @staticmethod
    def dns_error():
        return SimpleNamespace(
            returncode=1, stdout="", stderr="NameResolutionError: failed to resolve sensitive-value",
        )

    def test_retries_dns_failure_for_rest_get(self):
        for method in ("get", "GET"):
            with (
                self.subTest(method=method),
                patch("infra.DEADLINE", None),
                patch("infra.time.monotonic", return_value=100),
                patch("infra.subprocess.run", side_effect=[
                    self.dns_error(), SimpleNamespace(returncode=0, stdout='{"ok": true}'),
                ]) as run,
                patch("infra.time.sleep") as sleep,
                patch("sys.stderr", new_callable=io.StringIO) as stderr,
            ):
                self.assertEqual(infra.az("rest", "--method", method, "--url", "https://example.invalid"),
                                 {"ok": True})
                self.assertEqual(run.call_count, 2)
                sleep.assert_called_once_with(2)
                self.assertIn("DNS failure; retrying", stderr.getvalue())
                self.assertNotIn("sensitive-value", stderr.getvalue())

    def test_dns_retries_are_bounded_and_redact_final_error(self):
        with (
            patch("infra.DEADLINE", None),
            patch("infra.REDACTIONS", ["sensitive-value"]),
            patch("infra.time.monotonic", return_value=100),
            patch("infra.subprocess.run", return_value=self.dns_error()) as run,
            patch("infra.time.sleep") as sleep,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaises(RuntimeError) as caught:
                infra.az("rest", "--method", "get")
            self.assertEqual(run.call_count, 6)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4, 8, 16, 30])
            self.assertNotIn("sensitive-value", str(caught.exception))
            self.assertIn("<redacted>", str(caught.exception))

    def test_does_not_retry_mutating_commands(self):
        commands = [
            ("rest", "--method", method) for method in ("put", "post", "patch", "delete")
        ] + [("vm", "start"), ("vm", "deallocate"), ("group", "delete")]
        for command in commands:
            with (
                self.subTest(command=command),
                patch("infra.DEADLINE", None),
                patch("infra.subprocess.run", return_value=self.dns_error()) as run,
                patch("infra.time.sleep") as sleep,
            ):
                with self.assertRaises(RuntimeError):
                    infra.az(*command)
                run.assert_called_once()
                sleep.assert_not_called()

    def test_does_not_retry_other_errors_or_external_vm_stops(self):
        for error in ("AuthorizationFailed", "BadRequest", "OperationPreempted: VM deallocated"):
            with (
                self.subTest(error=error),
                patch("infra.DEADLINE", None),
                patch("infra.subprocess.run",
                      return_value=SimpleNamespace(returncode=1, stderr=error)) as run,
                patch("infra.time.sleep") as sleep,
            ):
                with self.assertRaisesRegex(RuntimeError, error):
                    infra.az("rest", "--method", "get")
                run.assert_called_once()
                sleep.assert_not_called()

    def test_expired_deadline_prevents_dispatch(self):
        with (
            patch("infra.DEADLINE", 99),
            patch("infra.time.monotonic", return_value=100),
            patch("infra.subprocess.run") as run,
        ):
            with self.assertRaisesRegex(TimeoutError, "Benchmark deadline reached"):
                infra.az("rest", "--method", "get")
            run.assert_not_called()

    def test_retries_share_the_original_deadline(self):
        with (
            patch("infra.DEADLINE", 110),
            patch("infra.time.monotonic", side_effect=[100, 100, 103, 105]),
            patch("infra.subprocess.run", side_effect=[
                self.dns_error(), SimpleNamespace(returncode=0, stdout="{}"),
            ]) as run,
            patch("infra.time.sleep") as sleep,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            infra.az("rest", "--method", "get")
            self.assertEqual([call.kwargs["timeout"] for call in run.call_args_list], [10, 5])
            sleep.assert_called_once_with(2)

    def test_dns_wait_must_fit_before_deadline(self):
        with (
            patch("infra.DEADLINE", 102),
            patch("infra.time.monotonic", return_value=100),
            patch("infra.subprocess.run", return_value=self.dns_error()) as run,
            patch("infra.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(TimeoutError, "before operation deadline"):
                infra.az("rest", "--method", "get")
            run.assert_called_once()
            sleep.assert_not_called()

    def test_cleanup_read_can_retry_after_benchmark_deadline(self):
        with (
            patch("infra.DEADLINE", 99),
            patch("infra.time.monotonic", return_value=100),
            patch("infra.subprocess.run", side_effect=[
                self.dns_error(), SimpleNamespace(returncode=0, stdout="{}"),
            ]) as run,
            patch("infra.time.sleep"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(infra.az("rest", "--method", "get", cleanup=True), {})
            self.assertEqual([call.kwargs["timeout"] for call in run.call_args_list], [3600, 3600])

    def test_subprocess_timeout_is_not_retried(self):
        with (
            patch("infra.DEADLINE", None),
            patch("infra.subprocess.run", side_effect=subprocess.TimeoutExpired("az", 10)) as run,
            patch("infra.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(TimeoutError, "Azure operation timed out"):
                infra.az("rest", "--method", "get")
            run.assert_called_once()
            sleep.assert_not_called()


class BenchmarkTests(unittest.TestCase):
    @staticmethod
    def timing_data():
        return {
            name: {"calls": "100", "p95_ms": "1.2", "p99_ms": "1.5"}
            for name in ("NEWORD", "PAYMENT", "DELIVERY", "SLEV", "OSTAT")
        }

    def measurement_log(self, users):
        return (
            f"{users + 1} Virtual Users Created with Monitor VU\n"
            f"Vuser 1:{users} Active Virtual Users configured\n"
            "Vuser 1:TEST RESULT : System achieved 123 NOPM from 456 PostgreSQL TPM\n"
            + "".join(f"Vuser {n}:FINISHED SUCCESS\n" for n in range(1, users + 2))
            + "ALL VIRTUAL USERS COMPLETE\n"
            "BENCHMARK_TIMING\n" + json.dumps(self.timing_data())
            + "\nBENCHMARK_RESULT\n"
        )

    def test_warehouse_count_uses_both_measured_sizes(self):
        self.assertEqual(run_benchmark.warehouse_count(300, [
            {"data_bytes": 100, "warehouses": 10},
            {"data_bytes": 200, "warehouses": 10},
        ]), 20)

    def test_warehouse_count_rejects_invalid_calibration(self):
        with self.assertRaises(ValueError):
            run_benchmark.warehouse_count(300, [{"data_bytes": 0, "warehouses": 10}])

    def test_primary_and_reader_endpoints(self):
        self.assertEqual(run_benchmark.endpoints({
            "properties": {"readWriteEndpoint": "a.horizondb.azure.com",
                           "readOnlyEndpoint": "b.horizondb.azure.com"},
        }), {"primary": "a.horizondb.azure.com", "reader": "b.horizondb.azure.com"})

    def test_endpoint_objects(self):
        self.assertEqual(run_benchmark.endpoints({
            "endpoints": [
                {"endpointType": "ReadWrite", "host": "a.horizondb.azure.com"},
                {"endpointType": "ReadOnly", "host": "b.horizondb.azure.com"},
            ],
        })["reader"], "b.horizondb.azure.com")

    def test_live_horizon_schema(self):
        self.assertEqual(run_benchmark.endpoints({
            "properties": {
                "fullyQualifiedDomainName": "cluster.id.japaneast.horizondb.azure.com",
                "readonlyEndpoint": "cluster.id.ro.japaneast.horizondb.azure.com",
            },
        })["primary"], "cluster.id.japaneast.horizondb.azure.com")

    def test_ambiguous_endpoints_fail(self):
        with self.assertRaises(RuntimeError):
            run_benchmark.endpoints({"hostname": "a.horizondb.azure.com"})

    def test_artifact_roundtrip(self):
        expected = {"ok": True, "result": {"nopm": 1200, "log": "full raw log"}}
        encoded = base64.b64encode(zlib.compress(json.dumps(expected).encode())).decode()
        self.assertEqual(run_benchmark.decode_result(encoded), expected)

    def test_script_counts_monitor_separately_and_keeps_standard_mix(self):
        script = worker.hammer_script("example.invalid", 500, users=128)
        self.assertIn("vuset vu 128\n", script)
        self.assertIn("vuset delay 0", script)
        self.assertIn("pg_allwarehouse true", script)
        self.assertIn("pg_timeprofile true", script)
        self.assertIn("pg_sslmode verify-full", script)
        self.assertIn("set jobid [lindex [split [vurun] =] end]", script)
        self.assertNotIn("pg_pass postgres", script)
        self.assertNotIn("PGPASSWORD", script)

    def test_build_users_never_exceed_warehouse_count(self):
        for warehouses in (1, 10, 16, 500):
            with self.subTest(warehouses=warehouses):
                script = worker.hammer_script("example.invalid", warehouses)
                self.assertIn(f"diset tpcc pg_num_vu {min(16, warehouses)}", script)
                self.assertIn("buildschema", script)

    def test_cleanup_rejects_wrong_group_name(self):
        with patch("infra.az") as azure:
            with self.assertRaises(RuntimeError):
                infra.check_group("production", "abc")
            azure.assert_not_called()

    def test_cleanup_rejects_missing_ownership_tag(self):
        with patch("infra.az", return_value={"tags": None}):
            with self.assertRaises(RuntimeError):
                infra.check_group("rg-horizon-bench-abc", "abc")

    def test_cleanup_checks_ownership_and_deletion(self):
        with patch("infra.az", side_effect=[
            True, {"tags": {"BenchmarkRun": "abc"}}, None, False
        ]) as azure:
            infra.cleanup("rg-horizon-bench-abc", "abc")
            self.assertEqual(azure.call_count, 4)
            self.assertEqual(azure.call_args_list[2].args[:2], ("group", "delete"))

    def test_cleanup_does_not_succeed_while_group_remains(self):
        with patch("infra.az", side_effect=[
            True, {"tags": {"BenchmarkRun": "abc"}}, None, True
        ]):
            with self.assertRaises(RuntimeError):
                infra.cleanup("rg-horizon-bench-abc", "abc")

    def test_telemetry_flags_a_single_saturated_core(self):
        telemetry = worker.Telemetry()
        telemetry.samples = [{
            "epoch": 10, "cpu_percent": 5, "busiest_core_percent": 99,
            "memory_available_percent": 80, "network_bytes_per_second": 100,
        }]
        self.assertTrue(telemetry.summary(0)["possible_client_limit"])

    def test_telemetry_requires_measurement_samples(self):
        with self.assertRaises(RuntimeError):
            worker.Telemetry().summary(0)

    def test_telemetry_excludes_shutdown_and_profile_collection(self):
        telemetry = worker.Telemetry()
        telemetry.samples = [
            {
                "epoch": epoch, "cpu_percent": cpu, "busiest_core_percent": cpu,
                "memory_available_percent": 80, "network_bytes_per_second": 100,
            }
            for epoch, cpu in ((125, 10), (415, 20), (600, 99))
        ]
        result = telemetry.summary(120, 420)
        self.assertEqual(result["cpu_p95_percent"], 20)
        self.assertFalse(result["possible_client_limit"])

    def test_run_command_failure_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = run_benchmark.Remote({
                "results": directory, "password": "secret", "subscription": "test",
                "run_id": "test", "group": "test",
            })
            job_id = "1234567890abcdef"
            payload = {"ok": False, "job": {
                "job_id": job_id, "format": 2, "run_id": "test",
                "operation": "measure", "host": "example.invalid",
            }, "error": "deliberate failure"}
            encoded = base64.b64encode(zlib.compress(json.dumps(payload).encode())).decode()
            checksum = hashlib.sha256(encoded.encode()).hexdigest()
            marker = f"BENCH_FILE:{job_id}.b64:{len(encoded)}:{checksum}\nBENCH_DATA:{encoded}"
            with (
                patch("run_benchmark.secrets.token_hex", return_value=job_id),
                patch.object(remote, "script", return_value={"exitCode": 1, "output": marker}),
            ):
                with self.assertRaisesRegex(RuntimeError, "deliberate failure"):
                    remote.job("vm", "measure", "example.invalid", key="test")
            artifacts = list(Path(directory).glob("measure-*.json"))
            self.assertEqual(len(artifacts), 1)
            self.assertFalse(json.loads(artifacts[0].read_text())["ok"])

    def test_more_than_25_commands_are_deleted_after_completion(self):
        remote = run_benchmark.Remote({
            "results": ".", "subscription": "test", "group": "test",
        })
        completed = {"properties": {"instanceView": {
            "executionState": "Succeeded", "exitCode": 0, "output": "result",
        }}}
        with patch("infra.az", side_effect=[None, completed, None] * 30) as azure:
            for _ in range(30):
                self.assertEqual(remote.script("vm", "echo result", 10)["exitCode"], 0)
            calls = azure.call_args_list
            self.assertEqual(len(calls), 90)
            for index in range(0, len(calls), 3):
                self.assertEqual(calls[index + 2].args[2], "delete")
                self.assertEqual(calls[index + 2].args[:3], ("vm", "run-command", "delete"))
                self.assertIn(
                    f"/runCommands/{calls[index + 2].args[8]}?", calls[index].args[4]
                )

    def test_failed_command_is_also_deleted(self):
        remote = run_benchmark.Remote({
            "results": ".", "subscription": "test", "group": "test",
        })
        with patch("infra.az", side_effect=[
            None, {"properties": {"provisioningState": "Failed"}}, None
        ]) as azure:
            with self.assertRaisesRegex(RuntimeError, "provisioning failed"):
                remote.script("vm", "false", 10)
            self.assertEqual(azure.call_args.args[2], "delete")

    def test_large_result_exceeding_25_chunks_does_not_accumulate_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = run_benchmark.Remote({
                "results": directory, "password": "secret", "subscription": "test",
                "group": "test", "run_id": "test",
            })
            job_id = "1234567890abcdef"
            payload = {
                "ok": True, "job": {
                    "job_id": job_id, "format": 2, "run_id": "test",
                    "operation": "build", "host": "example.invalid",
                },
                "result": {"log": random.Random(20261023).randbytes(100000).hex()},
            }
            encoded = base64.b64encode(zlib.compress(json.dumps(payload).encode())).decode()
            self.assertGreater(len(encoded), 25 * 3500)
            checksum = hashlib.sha256(encoded.encode()).hexdigest()
            marker = f"BENCH_FILE:{job_id}.b64:{len(encoded)}:{checksum}"
            live = {}
            created = 0
            maximum_live = 0

            def token_hex(size):
                nonlocal created
                if size == 8:
                    return job_id
                created += 1
                return f"{created:012x}"

            def azure(*args, **_):
                nonlocal maximum_live
                if args[:3] == ("vm", "run-command", "delete"):
                    del live[args[8]]
                    return None
                if args[:3] == ("vm", "run-command", "list"):
                    return [{"name": name} for name in live]
                url = args[4]
                name = url.split("/runCommands/")[1].split("?")[0]
                if args[2] == "put":
                    body = json.loads(Path(args[6][1:]).read_text())
                    script = body["properties"]["source"]["script"]
                    part = re.search(r"read_text\(\)\[(\d+):(\d+)\]", script)
                    output = (
                        "BENCH_CHUNK:" + encoded[int(part[1]):int(part[2])]
                        if part else marker
                    )
                    live[name] = output
                    maximum_live = max(maximum_live, len(live))
                    self.assertLessEqual(len(live), 25)
                    return None
                self.assertEqual(args[2], "get")
                return {"properties": {"instanceView": {
                    "executionState": "Succeeded", "exitCode": 0, "output": live[name],
                }}}

            with (
                patch("run_benchmark.secrets.token_hex", side_effect=token_hex),
                patch("infra.az", side_effect=azure),
            ):
                self.assertEqual(remote.job("vm", "build", "example.invalid", key="test"), payload["result"])
            self.assertGreater(created, 25)
            self.assertEqual(maximum_live, 1)
            self.assertEqual(live, {})

    def test_large_build_progress_is_explicitly_bounded(self):
        log = "BUILD CONFIGURATION\n" + "".join(
            f"Warehouse {index} loaded\n" for index in range(100000)
        ) + "BENCHADMIN SCHEMA COMPLETE\n"
        excerpt, omitted = worker.build_log_excerpt(log)
        self.assertIn("BUILD CONFIGURATION", excerpt)
        self.assertIn("SCHEMA COMPLETE", excerpt)
        self.assertEqual(omitted, len(log.splitlines()) - 100)
        self.assertIn(f"[{omitted} build progress lines omitted]", excerpt)
        encoded = base64.b64encode(zlib.compress(excerpt.encode()))
        self.assertLess(len(encoded), 3000)

    def test_measurement_logs_remain_complete_and_build_logs_remain_on_vm(self):
        log = "secret\n" + "".join(
            f"Progress {index}\n" for index in range(1000)
        ) + "SCHEMA COMPLETE\n" + self.measurement_log(1)
        redacted = log.replace("secret", "<redacted>")
        for users in (None, 1):
            with self.subTest(users=users), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with (
                    patch("worker.ROOT", root),
                    patch.dict(os.environ, {"DB_PASSWORD": "secret"}),
                    patch("worker.Telemetry") as telemetry,
                    patch("worker.ensure_open_file_limit", return_value=65536) as limit,
                    patch("worker.subprocess.run", return_value=SimpleNamespace(
                        returncode=0, stdout=log,
                    )),
                ):
                    telemetry.return_value.__enter__.return_value.summary.return_value = {
                        "cpu_p95_percent": 10,
                    }
                    result = worker.run_hammer({
                        "job_id": "test", "host": "example.invalid", "warehouses": 10,
                    }, users)
                    limit.assert_called_once_with()
                    self.assertEqual(result["open_file_soft_limit"], 65536)
                    telemetry.return_value.__enter__.return_value.summary.assert_called_once_with(
                        result["started_epoch"] + (120 if users is not None else 0),
                        result["started_epoch"] + 420 if users is not None else None,
                    )
                self.assertEqual((root / "test" / "hammerdb.log").read_text(), redacted)
                self.assertEqual(
                    result["full_log_sha256"], hashlib.sha256(redacted.encode()).hexdigest()
                )
                self.assertNotIn("telemetry_samples", result)
                if users is None:
                    self.assertGreater(result["log_omitted_lines"], 0)
                else:
                    self.assertEqual(result["log"], redacted)
                    self.assertEqual(result["log_omitted_lines"], 0)
                    self.assertEqual(result["nopm"], 123)

    def test_measurement_rejects_the_previous_off_by_one_user_count(self):
        with self.assertRaisesRegex(RuntimeError, "virtual-user count"):
            worker.measurement_result(self.measurement_log(2), 1)

    def test_open_file_limit_is_raised_without_changing_hard_limit(self):
        for soft, hard, expected in (
            (1024, 524288, 65536),
            (1024, resource.RLIM_INFINITY, 65536),
            (65536, 524288, 65536),
            (131072, 524288, 131072),
            (resource.RLIM_INFINITY, resource.RLIM_INFINITY, resource.RLIM_INFINITY),
        ):
            with (
                self.subTest(soft=soft, hard=hard),
                patch("worker.resource.getrlimit", return_value=(soft, hard)),
                patch("worker.resource.setrlimit") as setter,
            ):
                self.assertEqual(worker.ensure_open_file_limit(), expected)
                if soft == 1024:
                    setter.assert_called_once_with(resource.RLIMIT_NOFILE, (65536, hard))
                else:
                    setter.assert_not_called()

    def test_insufficient_hard_limit_fails_before_hammerdb_starts(self):
        with (
            patch("worker.resource.getrlimit", return_value=(1024, 4096)),
            patch("worker.resource.setrlimit") as setter,
            patch("worker.subprocess.run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "hard limit is 4096"):
                worker.run_hammer({})
            setter.assert_not_called()
            run.assert_not_called()

    def test_open_file_repair_reproduces_and_removes_1024_descriptor_ceiling(self):
        result = subprocess.run(
            [sys.executable, "-c", r'''
from contextlib import ExitStack
import errno
import resource
import worker
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))
try:
    with ExitStack() as stack:
        for _ in range(1100):
            stack.enter_context(open("/dev/null", "rb"))
except OSError as error:
    assert error.errno == errno.EMFILE, error
else:
    raise AssertionError("The inherited 1024-file limit was not reproduced")
assert worker.ensure_open_file_limit() >= 65536
with ExitStack() as stack:
    for _ in range(2048):
        stack.enter_context(open("/dev/null", "rb"))
print("DESCRIPTOR_REPAIR_OK")
'''],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DESCRIPTOR_REPAIR_OK", result.stdout)

    def test_measurement_rejects_missing_failed_or_duplicate_workers(self):
        log = self.measurement_log(256)
        for broken in (
            log.replace("Vuser 257:FINISHED SUCCESS\n", ""),
            log.replace("Vuser 257:FINISHED SUCCESS", "Vuser 257:FINISHED FAILED"),
            log + "Vuser 256:FINISHED SUCCESS\n",
            log + "Error in Virtual User 252: unable to open database file\n",
            log + "WARNING:Timing Data Incomplete\n",
            log + "ERROR:Timing Gather Timed Out before any Virtual User Reported\n",
        ):
            with self.subTest(tail=broken[-100:]), self.assertRaisesRegex(
                RuntimeError, "execution or timing gather failed"
            ):
                worker.measurement_result(broken, 256)

    def test_measurement_requires_completion_and_all_transaction_profiles(self):
        log = self.measurement_log(1)
        for broken, message in (
            (log.replace("ALL VIRTUAL USERS COMPLETE", ""), "did not complete"),
            (log.replace("BENCHMARK_RESULT", ""), "did not export"),
            (log.replace(json.dumps(self.timing_data()), "{}"), "incomplete"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                worker.measurement_result(broken, 1)

    def test_measurement_rejects_invalid_or_missing_latency_values(self):
        for changes in (
            {"calls": "bad"}, {"p99_ms": "NaN"}, {"p99_ms": "0.1"}, {"calls": "0"},
        ):
            with self.subTest(changes=changes):
                timings = self.timing_data()
                timings["NEWORD"].update(changes)
                log = self.measurement_log(1).replace(
                    json.dumps(self.timing_data()), json.dumps(timings)
                )
                with self.assertRaisesRegex(RuntimeError, "timing"):
                    worker.measurement_result(log, 1)

    def test_tcl_waits_for_asynchronous_completion_before_export_and_destruction(self):
        prefix = r'''
set complete false
set workers 0
set events {}
proc dbset {args} {}
proc diset {args} {}
proc loadscript {} {}
proc vuset {option value} {
    if {$option eq "vu"} {set ::workers $value}
    if {$option eq "delay" && $value != 0} {error "Nonzero startup delay"}
}
proc vucreate {} {
    puts "[expr {$::workers + 1}] Virtual Users Created with Monitor VU"
}
proc finish {} {
    set ::complete true
    puts "Vuser 1:$::workers Active Virtual Users configured"
    puts "Vuser 1:TEST RESULT : System achieved 123 NOPM from 456 PostgreSQL TPM"
    for {set n 1} {$n <= $::workers + 1} {incr n} {
        puts "Vuser $n:FINISHED SUCCESS"
    }
    puts "ALL VIRTUAL USERS COMPLETE"
}
proc vurun {} {
    after 0 finish
    return "Benchmark Run jobid=TEST"
}
proc vucomplete {} {return $::complete}
proc job {id operation} {
    if {$id ne "TEST" || !$::complete} {error "Results queried before completion"}
    lappend ::events $operation
    if {$operation eq "timing"} {puts {TIMING_DATA}}
}
proc vudestroy {} {
    if {!$::complete} {error "Virtual users aborted before completion"}
    lappend ::events destroy
}
'''
        suffix = '''
if {$events ne {timing result destroy}} {error "Incorrect export/destruction order"}
puts TCL_REGRESSION_OK
'''
        for users in (1, 256):
            with self.subTest(users=users), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "driver.tcl"
                path.write_text(
                    prefix.replace("TIMING_DATA", json.dumps(self.timing_data()))
                    + worker.hammer_script("example.invalid", 517, users=users) + suffix
                )
                result = subprocess.run(
                    ["tclsh", str(path)], capture_output=True, text=True, timeout=10,
                    env=dict(os.environ, DB_PASSWORD="secret"),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("TCL_REGRESSION_OK", result.stdout)
                parsed = worker.measurement_result(result.stdout, users)
                self.assertEqual(parsed["active_users"], users)
                self.assertEqual(parsed["monitor_users"], 1)
                self.assertEqual(parsed["timings"], self.timing_data())

    def test_tcl_completion_wait_is_bounded_and_does_not_export_partial_results(self):
        prefix = r'''
set complete false
set simulated_time 0
proc dbset {args} {}
proc diset {args} {}
proc loadscript {} {}
proc vuset {args} {}
proc vucreate {} {}
proc vurun {} {return "Benchmark Run jobid=TEST"}
proc vucomplete {} {return false}
rename clock native_clock
proc clock {args} {incr ::simulated_time 600001}
proc job {args} {puts INVALID_PARTIAL_RESULT}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "driver.tcl"
            path.write_text(prefix + worker.hammer_script("example.invalid", 517, users=1))
            result = subprocess.run(
                ["tclsh", str(path)], capture_output=True, text=True, timeout=10,
                env=dict(os.environ, DB_PASSWORD="secret"),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Timed out waiting for HammerDB", result.stderr)
            self.assertNotIn("INVALID_PARTIAL_RESULT", result.stdout)

    def test_worker_encoder_matches_inline_and_chunked_controller_protocol(self):
        for size in (64, 100000):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                result = {"log": random.Random(1).randbytes(size).hex()}
                job = {"operation": "metadata", "job_id": "1234567890abcdef", "format": 2}
                output = io.StringIO()
                with (
                    patch("worker.ROOT", Path(directory)),
                    patch.dict(os.environ, {"JOB": json.dumps(job), "DB_PASSWORD": "secret"}),
                    patch("worker.metadata", return_value=result),
                    patch("sys.stdout", output),
                    patch("sys.argv", ["worker.py"]),
                ):
                    worker.main()
                encoded = (Path(directory) / f"{job['job_id']}.b64").read_text()
                self.assertEqual(run_benchmark.decode_result(encoded)["result"], result)
                self.assertEqual("BENCH_DATA:" in output.getvalue(), len(encoded) <= 3500)
                self.assertLess(len(output.getvalue().encode()), 4096)
                checksum = hashlib.sha256(encoded.encode()).hexdigest()
                self.assertIn(f":{len(encoded)}:{checksum}", output.getvalue())


if __name__ == "__main__":
    unittest.main()
