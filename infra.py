"""Provision, resume, pause and explicitly clean up an isolated benchmark."""

import argparse
from contextlib import contextmanager
import ctypes
import datetime as dt
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from durable import FORMAT, atomic_json, run_lock


SUBSCRIPTION = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
REGION = "japaneast"
VM_SIZE = "Standard_F32as_v6"
TIME_LIMIT_SECONDS = 16 * 3600
DEADLINE = None
REDACTIONS = []
RESULTS = Path(__file__).with_name("results")


class KeychainCredentials:
    """Use the macOS login Keychain without putting passwords in process argv."""

    SERVICE = b"horizon-bench"

    def __init__(self):
        if sys.platform != "darwin":
            raise RuntimeError("This run uses macOS Keychain; use the original Mac to resume or "
                               "remove its credential")
        self.api = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        pointer = ctypes.c_void_p
        self.api.SecKeychainFindGenericPassword.argtypes = [
            pointer, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(pointer), ctypes.POINTER(pointer),
        ]
        self.api.SecKeychainAddGenericPassword.argtypes = [
            pointer, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(pointer),
        ]
        self.api.SecKeychainItemFreeContent.argtypes = [pointer, pointer]
        self.api.SecKeychainItemDelete.argtypes = [pointer]
        self.api.CFRelease.argtypes = [pointer]
        self.api.CFRelease.restype = None

    def find(self, account):
        length, data, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
        account = account.encode()
        status = self.api.SecKeychainFindGenericPassword(
            None, len(self.SERVICE), self.SERVICE, len(account), account,
            ctypes.byref(length), ctypes.byref(data), ctypes.byref(item),
        )
        if status == -25300:
            return None, None
        if status:
            raise RuntimeError(f"Keychain lookup failed (OSStatus {status})")
        try:
            return ctypes.string_at(data, length.value).decode(), item
        finally:
            self.api.SecKeychainItemFreeContent(None, data)

    def get(self, account):
        value, item = self.find(account)
        if item:
            self.api.CFRelease(item)
        if value is None:
            raise RuntimeError("Run credential is missing from Keychain; cannot resume")
        return value

    def create(self, account):
        previous, item = self.find(account)
        if item:
            self.api.CFRelease(item)
        if previous is not None:
            raise RuntimeError("Refusing to replace an existing run credential")
        value = "B9!" + secrets.token_urlsafe(28)
        account_bytes, password = account.encode(), value.encode()
        status = self.api.SecKeychainAddGenericPassword(
            None, len(self.SERVICE), self.SERVICE, len(account_bytes), account_bytes,
            len(password), password, None,
        )
        if status:
            raise RuntimeError(f"Keychain write failed (OSStatus {status}); no deployment started")
        if self.get(account) != value:
            raise RuntimeError("Keychain round-trip failed; no deployment started")
        return value

    def delete(self, account):
        _, item = self.find(account)
        if item:
            try:
                status = self.api.SecKeychainItemDelete(item)
                if status:
                    raise RuntimeError(f"Keychain deletion failed (OSStatus {status})")
            finally:
                self.api.CFRelease(item)


class FileCredentials:
    """Keep generated passwords outside results in owner-only POSIX files."""

    def __init__(self):
        self.path = Path.home() / ".horizon-bench-credentials"

    @contextmanager
    def directory(self, create=False):
        if create:
            try:
                self.path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        try:
            descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            yield None
            return
        try:
            info = os.fstat(descriptor)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "Credential directory must be owned by the current user with mode 0700")
            yield descriptor
        finally:
            os.close(descriptor)

    def filename(self, account):
        require(bool(re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/[0-9a-f]{8}", account,
        )), "Invalid credential account")
        return account.replace("/", "-")

    def read(self, directory, account):
        name = self.filename(account)
        if directory is None:
            return None
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor) as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "Credential file must be a regular, single-link file owned by the "
                    "current user with mode 0600")
            value = stream.read(128)
        require(bool(re.fullmatch(r"B9![A-Za-z0-9_-]{38}\n", value)),
                "Credential file is invalid; refusing to use or overwrite it")
        return value.rstrip("\n")

    def get(self, account):
        with self.directory() as directory:
            value = self.read(directory, account)
        require(value is not None, "Run credential file is missing; cannot resume")
        return value

    def create(self, account):
        name = self.filename(account)
        with self.directory(create=True) as directory:
            try:
                descriptor = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=directory,
                )
            except FileExistsError:
                raise RuntimeError("Refusing to replace an existing run credential") from None
            value = "B9!" + secrets.token_urlsafe(28)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(value + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
            require(self.read(directory, account) == value,
                    "Credential file round-trip failed; no deployment started")
        return value

    def delete(self, account):
        with self.directory() as directory:
            if self.read(directory, account) is not None:
                os.unlink(self.filename(account), dir_fd=directory)
                os.fsync(directory)


def default_credential_store():
    return "keychain" if sys.platform == "darwin" else "file"


class Credentials:
    def __init__(self, backend=None):
        if backend is None:
            backend = default_credential_store()
        if backend == "keychain":
            self.store = KeychainCredentials()
        elif backend == "file":
            self.store = FileCredentials()
        else:
            raise RuntimeError(f"Unknown credential store: {backend}")

    def get(self, account):
        return self.store.get(account)

    def create(self, account):
        return self.store.create(account)

    def delete(self, account):
        self.store.delete(account)


def az(*args, secret=False, cleanup=False):
    command = ["az", *args, "--subscription", SUBSCRIPTION, "-o", "json"]
    operation_deadline = time.monotonic() + 3600
    if DEADLINE is not None and not cleanup:
        operation_deadline = min(operation_deadline, DEADLINE)
    read_only = args[:2] == ("rest", "--method") and len(args) > 2 and args[2].lower() == "get"
    retry_delays = (2, 4, 8, 16, 30)
    for attempt in range(len(retry_delays) + 1):
        timeout = operation_deadline - time.monotonic()
        if timeout <= 0:
            if DEADLINE is not None and not cleanup and DEADLINE <= operation_deadline:
                raise TimeoutError("Benchmark deadline reached")
            raise TimeoutError(f"Azure operation timed out: {' '.join(command[:3])}")
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Azure operation timed out: {' '.join(command[:3])}") from None
        if not result.returncode:
            return json.loads(result.stdout) if result.stdout.strip() else None
        error = result.stderr
        for value in REDACTIONS:
            error = error.replace(value, "<redacted>")
        dns_failure = any(marker in error.lower() for marker in (
            "nameresolutionerror", "failed to resolve", "temporary failure in name resolution",
        ))
        if not (read_only and dns_failure and attempt < len(retry_delays)):
            raise RuntimeError(f"{' '.join(command[:3])}: {error}")
        delay = retry_delays[attempt]
        if operation_deadline - time.monotonic() <= delay:
            raise TimeoutError("Insufficient time for Azure DNS retry before operation deadline")
        print(f"Azure REST GET DNS failure; retrying in {delay}s "
              f"({attempt + 1}/{len(retry_delays)})", file=sys.stderr, flush=True)
        time.sleep(delay)


def check_group(group, run_id):
    if group != f"rg-horizon-bench-{run_id}":
        raise RuntimeError("Resource group name does not match this run")
    group_data = az("group", "show", "-n", group, cleanup=True)
    if (group_data.get("tags") or {}).get("BenchmarkRun") != run_id:
        raise RuntimeError("Resource group is not owned by this run")


def cleanup(group, run_id):
    if not az("group", "exists", "-n", group, cleanup=True):
        return
    check_group(group, run_id)
    az("group", "delete", "-n", group, "--yes", cleanup=True)
    if az("group", "exists", "-n", group, cleanup=True):
        raise RuntimeError(f"Cleanup incomplete: {group} still exists")


def install_watchdog(group, run_id, expires):
    vm = az("vm", "show", "-g", group, "-n", "bench-client-1")
    scope = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
    for role, target_scope in [
        ("Reader", scope),
        *[
            ("Virtual Machine Contributor", f"{scope}/providers/Microsoft.Compute/virtualMachines/bench-client-{n}")
            for n in (1, 2)
        ],
    ]:
        assignment = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{vm['identity']['principalId']}:{role}:{target_scope}"))
        az(
            "role", "assignment", "create", "--name", assignment, "--assignee-object-id",
            vm["identity"]["principalId"], "--assignee-principal-type",
            "ServicePrincipal", "--role", role, "--scope", target_scope,
        )
    source = Path(__file__).with_name("watchdog.py").read_text()
    script = (
        "set -eu\ninstall -d -m 700 /opt/horizon-bench\n"
        "cat > /opt/horizon-bench/watchdog.py <<'PYTHON'\n"
        + source + "\nPYTHON\n"
        + f"python3 /opt/horizon-bench/watchdog.py {SUBSCRIPTION} {group} {run_id} --check\n"
        + "cat > /etc/systemd/system/benchmark-pause.service <<'UNIT'\n"
        + "[Unit]\nDescription=Pause retained benchmark clients\n[Service]\nType=oneshot\n"
        + f"ExecStart=/usr/bin/python3 /opt/horizon-bench/watchdog.py {SUBSCRIPTION} {group} {run_id}\nUNIT\n"
        + "cat > /etc/systemd/system/benchmark-pause.timer <<'UNIT'\n"
        + f"[Unit]\nDescription=Benchmark pause deadline\n[Timer]\nOnCalendar={expires}\n"
        + "Persistent=true\n[Install]\nWantedBy=timers.target\nUNIT\n"
        + "systemctl daemon-reload\nsystemctl enable benchmark-pause.timer\n"
        + "systemctl restart benchmark-pause.timer\nsystemctl is-active benchmark-pause.timer\n"
    )
    result = az(
        "vm", "run-command", "invoke", "-g", group, "-n", "bench-client-1",
        "--command-id", "RunShellScript", "--scripts", script,
    )
    output = "\n".join(item.get("message", "") for item in result["value"])
    if "WATCHDOG_ACCESS_OK" not in output or "active" not in output:
        raise RuntimeError(f"Pause watchdog was not verified: {output}")


def save_state(state):
    atomic_json(RESULTS / state["run_id"] / "state.json", state)


def ensure_resource(state, kind, name, create, show, validate):
    resources = state.setdefault("resources", {})
    inventory = az("resource", "list", "-g", state["group"])
    exists = any(r["name"] == name and r["type"].lower() == kind.lower() for r in inventory)
    if not exists:
        if resources.get(name) == "ready":
            raise RuntimeError(f"Previously provisioned resource is missing: {name}; refusing to recreate")
        resources[name] = "creating"
        save_state(state)
        az(*create)
    until = time.monotonic() + 3600
    while time.monotonic() < until:
        data = az(*show)
        status = data.get("state") or data.get("properties", {}).get("provisioningState")
        if status is None:
            status = data.get("provisioningState")
        if status in ("Failed", "Canceled", "Dropping", "Deleting", "Disabled"):
            raise RuntimeError(f"Resource is not resumable: {name}: {status}")
        if status in ("Ready", "Succeeded"):
            validate(data)
            resources[name] = "ready"
            save_state(state)
            return data
        time.sleep(15)
    raise TimeoutError(f"Resource did not become ready: {name}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def client_power(group, name):
    view = az("vm", "get-instance-view", "-g", group, "-n", name, cleanup=True)
    powers = [s["code"] for s in view["instanceView"]["statuses"] if s["code"].startswith("PowerState/")]
    if len(powers) != 1:
        raise RuntimeError(f"Cannot determine client power state: {name}")
    return powers[0]


def pause_clients(state):
    if not az("group", "exists", "-n", state["group"], cleanup=True):
        return
    check_group(state["group"], state["run_id"])
    inventory = az("resource", "list", "-g", state["group"], cleanup=True)
    for name in ("bench-client-2", "bench-client-1"):
        matches = [r for r in inventory if r["type"].lower() == "microsoft.compute/virtualmachines" and r["name"] == name]
        if matches:
            require((matches[0].get("tags") or {}).get("BenchmarkRun") == state["run_id"],
                    f"Refusing to pause a foreign client: {name}")
            az("vm", "deallocate", "-g", state["group"], "-n", name, cleanup=True)
            require(client_power(state["group"], name) == "PowerState/deallocated",
                    f"Client deallocation was not verified: {name}")


def provision(state, password, start_clients=False):
    group, run_id = state["group"], state["run_id"]
    expires = dt.datetime.fromisoformat(state["expires_utc"])
    ensure_resource(
        state, "Microsoft.Network/virtualNetworks", "bench-vnet",
        ("network", "vnet", "create", "-g", group, "-n", "bench-vnet",
         "--address-prefixes", "10.230.0.0/16", "--subnet-name", "bench-subnet", "--subnet-prefixes", "10.230.1.0/24"),
        ("network", "vnet", "show", "-g", group, "-n", "bench-vnet"),
        lambda d: require(d["addressSpace"]["addressPrefixes"] == ["10.230.0.0/16"]
                          and any(s["name"] == "bench-subnet" and s["addressPrefix"] == "10.230.1.0/24"
                                  for s in d["subnets"]), "Unexpected benchmark network"),
    )
    vm_ips = []
    with tempfile.TemporaryDirectory(prefix="horizon-bench-ssh-") as key_dir:
        key = Path(key_dir) / "client"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        for index in (1, 2):
            name = f"bench-client-{index}"
            print(f"Provisioning {name} ({VM_SIZE})", flush=True)
            ensure_resource(
                state, "Microsoft.Compute/virtualMachines", name,
                ("vm", "create", "-g", group, "-n", name, "--image",
                "Canonical:ubuntu-24_04-lts:server:latest", "--size", VM_SIZE,
                "--admin-username", "benchadmin", "--ssh-key-values",
                str(key.with_suffix(".pub")),
                "--vnet-name", "bench-vnet", "--subnet", "bench-subnet",
                "--public-ip-sku", "Standard", "--nsg-rule", "NONE",
                "--assign-identity",
                "--tags", f"BenchmarkRun={run_id}"),
                ("vm", "show", "-g", group, "-n", name),
                lambda d: require(d["hardwareProfile"]["vmSize"] == VM_SIZE
                                  and (d.get("tags") or {}).get("BenchmarkRun") == run_id
                                  and d.get("identity", {}).get("principalId"),
                                  "Client configuration or ownership changed"),
            )
            power = client_power(group, name)
            if power != "PowerState/running":
                require(start_clients and power in ("PowerState/deallocated", "PowerState/stopped"),
                        f"{name} is stopped; confirm the external stop, then use --start-clients")
                az("vm", "start", "-g", group, "-n", name)
                require(client_power(group, name) == "PowerState/running", f"Client did not start: {name}")
            ip = az("vm", "show", "-g", group, "-n", name, "-d")["publicIps"]
            require(bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip)), "Client must have one public egress IP")
            vm_ips.append(ip)

    print("Verifying non-destructive client pause timer", flush=True)
    install_watchdog(group, run_id, expires.strftime("%Y-%m-%d %H:%M:%S UTC"))
    remaining = DEADLINE - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Benchmark deadline reached before transport preflight")
    preflight = {
        "group": group, "subscription": SUBSCRIPTION,
        "client_vms": ["bench-client-1", "bench-client-2"],
        "results": str(Path(__file__).with_name("results") / run_id),
        "deadline_epoch": time.time() + remaining,
    }
    if not state.get("transport_verified"):
        subprocess.run(
            [sys.executable, str(Path(__file__).with_name("run_benchmark.py")), "--preflight"],
            env=dict(os.environ, BENCH_CONFIG=json.dumps(preflight)),
            check=True, timeout=min(600, remaining),
        )
        state["transport_verified"] = True
        save_state(state)
    horizon = f"hdbench{run_id}"
    flexible = f"fsbench{run_id}"
    print(f"Provisioning HorizonDB {horizon}", flush=True)
    ensure_resource(
        state, "Microsoft.HorizonDb/clusters", horizon,
        ("horizondb", "create", "-g", group, "-n", horizon, "-l", REGION,
        "--administrator-login", "benchadmin",
        "--administrator-login-password", password, "--version", "17",
        "--v-cores", "8", "--replica-count", "2", "--public-access",
        vm_ips[0], "--yes"),
        ("horizondb", "show", "-g", group, "-n", horizon),
        lambda d: require(d["properties"]["vCores"] == 8 and d["properties"]["replicaCount"] == 2
                          and d["properties"]["version"] == "17"
                          and d["properties"]["administratorLogin"] == "benchadmin",
                          "HorizonDB compute configuration changed"),
    )
    for index, ip in enumerate(vm_ips, 1):
        az(
            "horizondb", "firewall-rule", "create", "-g", group,
            "--cluster-name", horizon, "-n", f"client{index}",
            "--start-ip-address", ip, "--end-ip-address", ip,
        )
    print(f"Provisioning Flexible Server {flexible}", flush=True)
    validate_flexible = lambda d: require(
        d["sku"] == {"name": "Standard_E8ds_v5", "tier": "MemoryOptimized"}
        and d["version"].split(".")[0] == "17"
        and d["administratorLogin"] == "benchadmin"
        and all(d["storage"][key] == value for key, value in {
            "storageSizeGb": 2048, "type": "PremiumV2_LRS", "iops": 12000, "throughput": 280,
        }.items()),
        "Flexible Server configuration changed",
    )
    ensure_resource(
        state, "Microsoft.DBforPostgreSQL/flexibleServers", flexible,
        ("postgres", "flexible-server", "create", "-g", group, "-n", flexible,
        "-l", REGION, "--tier", "MemoryOptimized", "--sku-name",
        "Standard_E8ds_v5", "--version", "17", "--storage-size", "2048",
        "--storage-type", "PremiumV2_LRS", "--iops", "12000",
        "--throughput", "280",
        "--admin-user", "benchadmin", "--admin-password", password,
        "--public-access", vm_ips[0], "--yes"),
        ("postgres", "flexible-server", "show", "-g", group, "-n", flexible),
        validate_flexible,
    )
    for index, ip in enumerate(vm_ips, 1):
        az(
            "postgres", "flexible-server", "firewall-rule", "create",
            "-g", group, "-n", f"client{index}", "--server-name", flexible,
            "--start-ip-address", ip, "--end-ip-address", ip,
        )
    print(f"Provisioning Flexible Server read replica {flexible}-replica", flush=True)
    ensure_resource(
        state, "Microsoft.DBforPostgreSQL/flexibleServers", f"{flexible}-replica",
        ("postgres", "flexible-server", "replica", "create", "-g", group,
        "-n", f"{flexible}-replica", "--source-server", flexible, "-l",
        REGION, "--yes"),
        ("postgres", "flexible-server", "show", "-g", group, "-n", f"{flexible}-replica"),
        validate_flexible,
    )
    for index, ip in enumerate(vm_ips, 1):
        az(
            "postgres", "flexible-server", "firewall-rule", "create",
            "-g", group, "-n", f"client{index}", "--server-name",
            f"{flexible}-replica", "--start-ip-address", ip, "--end-ip-address", ip,
        )
    return {
        "horizon": horizon,
        "flexible": flexible,
        "flexible_replica": f"{flexible}-replica",
        "client_vms": ["bench-client-1", "bench-client-2"],
        "password": password,
        "run_id": run_id,
    }


def main():
    global DEADLINE
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark", type=Path, nargs="?", help="Local benchmark runner (new run)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--resume", metavar="RUN_ID")
    action.add_argument("--cleanup", metavar="RUN_ID")
    parser.add_argument("--start-clients", action="store_true", help="Explicitly start stopped clients once")
    parser.add_argument("--extend-hours", type=float, help="Explicitly extend a retained run's pause deadline")
    parser.add_argument("--credential-store", choices=("keychain", "file"),
                        help="New runs only; default: keychain on macOS, file on Linux/WSL")
    args = parser.parse_args()
    if (args.resume or args.cleanup) and args.benchmark:
        parser.error("A retained run uses its saved benchmark runner; omit the positional argument")
    if (args.start_clients or args.extend_hours is not None) and not args.resume:
        parser.error("--start-clients and --extend-hours require --resume")
    if args.credential_store is not None and (args.resume or args.cleanup):
        parser.error("--credential-store is for new runs; retained runs use their saved store")
    if args.extend_hours is not None and not 0 < args.extend_hours <= 72:
        parser.error("--extend-hours must be greater than zero and at most 72")
    try:
        if str(uuid.UUID(SUBSCRIPTION)) != SUBSCRIPTION.lower():
            raise ValueError
    except ValueError:
        parser.error("Set AZURE_SUBSCRIPTION_ID to a valid subscription UUID")
    run_id = args.resume or args.cleanup or secrets.token_hex(4)
    if not re.fullmatch("[a-f0-9]{8}", run_id):
        parser.error("RUN_ID must be eight lowercase hexadecimal characters")
    results = RESULTS / run_id
    if args.resume or args.cleanup:
        if not (results / "state.json").is_file():
            parser.error("Run state does not exist")
    elif args.benchmark is None or not args.benchmark.resolve().is_file():
        parser.error("Benchmark runner must exist before provisioning")
    results.mkdir(parents=True, exist_ok=bool(args.resume or args.cleanup))
    with run_lock(results):
        state_file = results / "state.json"
        if args.resume or args.cleanup:
            state = json.loads(state_file.read_text())
            require(state["run_id"] == run_id and state["subscription"] == SUBSCRIPTION
                    and state["group"] == f"rg-horizon-bench-{run_id}", "Run identity does not match")
            if state.get("format") == FORMAT:
                require(state["credential_account"] == f"{SUBSCRIPTION}/{run_id}",
                        "Credential reference does not match this run")
                require(state.get("credential_store", "keychain") in ("keychain", "file"),
                        "Unknown saved credential store")
        else:
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=TIME_LIMIT_SECONDS)
            state = {
                "format": FORMAT, "group": f"rg-horizon-bench-{run_id}",
                "run_id": run_id, "subscription": SUBSCRIPTION,
                "expires_utc": expires.isoformat(), "phase": "preparing",
                "benchmark": str(args.benchmark.resolve()),
                "credential_account": f"{SUBSCRIPTION}/{run_id}",
                "credential_store": args.credential_store or default_credential_store(),
            }
            save_state(state)
        if args.cleanup:
            finish_cleanup(state)
            return
        require(state.get("format") == FORMAT and state["phase"] != "deleted",
                "Deleted or legacy runs cannot be resumed")
        if args.resume:
            require(az("group", "exists", "-n", state["group"]),
                    "Retained group is missing; it will not be recreated")
            check_group(state["group"], run_id)
            manifest_path = results / "manifest.json"
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text())
                if manifest.get("format") == FORMAT and manifest.get("status") == "completed":
                    state["outcome"] = "completed"
                    finish_cleanup(state)
                    return
        if args.extend_hours is not None:
            previous = dt.datetime.fromisoformat(state["expires_utc"])
            expires_utc = (
                max(previous, dt.datetime.now(dt.timezone.utc)) + dt.timedelta(hours=args.extend_hours)
            ).isoformat()
            az("group", "update", "-n", state["group"], "--set",
               f"tags.ExpiresUTC={expires_utc}")
            state["expires_utc"] = expires_utc
            save_state(state)
        remaining = dt.datetime.fromisoformat(state["expires_utc"]).timestamp() - time.time() - 3600
        require(remaining > 0, "Execution window expired; review retained costs and use --extend-hours")
        DEADLINE = time.monotonic() + remaining
        store = Credentials(state.get("credential_store", "keychain"))
        password = store.get(state["credential_account"]) if args.resume else store.create(state["credential_account"])
        REDACTIONS.append(password)
        execute(state, password, args)


def finish_cleanup(state):
    state["phase"] = "cleaning"
    save_state(state)
    cleanup(state["group"], state["run_id"])
    state["phase"] = "deleted"
    state["deleted_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    save_state(state)
    if state.get("credential_account"):
        Credentials(state.get("credential_store", "keychain")).delete(state["credential_account"])
        state["credential_removed"] = True
        save_state(state)


def execute(state, password, args):
    group, run_id = state["group"], state["run_id"]
    original = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit("Terminated; retaining resumable resources"))
    try:
        manifest_path = RESULTS / run_id / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("format") == FORMAT and manifest.get("status") == "completed":
                state["outcome"] = "completed"
                finish_cleanup(state)
                return
        if not args.resume:
            require(not az("group", "exists", "-n", group), "Refusing to reuse an existing group")
            az("group", "create", "-n", group, "-l", REGION,
               "--tags", f"BenchmarkRun={run_id}", f"ExpiresUTC={state['expires_utc']}")
            check_group(group, run_id)
        state["phase"] = "provisioning"
        save_state(state)
        config = provision(state, password, args.start_clients)
        config.update(
            group=group, subscription=SUBSCRIPTION, results=str(RESULTS / run_id),
            deadline_epoch=time.time() + max(0, DEADLINE - time.monotonic()),
        )
        env = dict(os.environ, BENCH_CONFIG=json.dumps(config))
        state["phase"] = "benchmarking"
        state["clients_paused"] = False
        state.pop("pause_error", None)
        save_state(state)
        remaining = max(0, DEADLINE - time.monotonic())
        runner = Path(state["benchmark"])
        require(runner.is_file(), "Saved benchmark runner is missing")
        process = subprocess.Popen([sys.executable, str(runner)], env=env)
        try:
            code = process.wait(timeout=remaining)
            require(code == 0, f"Benchmark controller exited {code}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        manifest = json.loads((RESULTS / run_id / "manifest.json").read_text())
        require(manifest.get("status") == "completed" and manifest.get("format") == FORMAT,
                "Benchmark did not durably confirm completion")
        state["outcome"] = "completed"
        state.pop("error", None)
        save_state(state)
        finish_cleanup(state)
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        state["phase"] = "paused" if state.get("phase") != "deleted" else "deleted"
        if state.get("outcome") != "completed":
            state["outcome"] = "paused"
        state["error"] = str(error).replace(password, "<redacted>")
        save_state(state)
        if state["phase"] != "deleted":
            state["clients_paused"] = False
            try:
                pause_clients(state)
                state["clients_paused"] = True
            except Exception as pause_error:
                state["pause_error"] = str(pause_error).replace(password, "<redacted>")
                print(f"Client pause failed: {state['pause_error']}", file=sys.stderr, flush=True)
            save_state(state)
            print(f"Resources and data retained; DB/storage charges continue. Resume: "
                  f"python3 infra.py --resume {run_id} --start-clients\n"
                  f"Explicit cleanup: python3 infra.py --cleanup {run_id}", file=sys.stderr, flush=True)
        raise
    finally:
        signal.signal(signal.SIGTERM, original)


if __name__ == "__main__":
    main()
