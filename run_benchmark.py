"""Run the approved TPROC-C comparison; persist every result before cleanup."""

import base64
from concurrent.futures import ThreadPoolExecutor
import csv
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import statistics
import sys
import tempfile
import time
import zlib

import infra
from durable import FORMAT, Journal, atomic_json, atomic_text


STAGES = (50, 250, 1024)
USERS = (1, 8, 16, 32, 64, 128, 256)


def warehouse_count(target_bytes, calibrations):
    if target_bytes <= 0 or any(item["warehouses"] <= 0 for item in calibrations):
        raise ValueError("Target and calibration warehouse counts must be positive")
    per_warehouse = [
        item["data_bytes"] / item["warehouses"] for item in calibrations
    ]
    if not per_warehouse or min(per_warehouse) <= 0:
        raise ValueError("Calibration must contain positive measured data sizes")
    return math.ceil(target_bytes / statistics.mean(per_warehouse))


def decode_result(encoded):
    return json.loads(zlib.decompress(base64.b64decode(encoded, validate=True)))


def endpoints(cluster):
    found = {}

    def walk(value, path=""):
        if isinstance(value, dict):
            labels = " ".join(
                str(value.get(key, "")) for key in ("name", "type", "endpointType", "role")
            )
            for key, child in value.items():
                walk(child, f"{path}/{key} {labels}")
        elif isinstance(value, list):
            for child in value:
                walk(child, path)
        elif isinstance(value, str) and value.endswith(".horizondb.azure.com"):
            key = re.sub(r"[^a-z]", "", path.lower())
            if any(label in key for label in ("readonly", "reader", "standby")):
                found["reader"] = value
            elif any(label in key for label in (
                "readwrite", "primary", "writer", "fullyqualifieddomainname"
            )):
                found["primary"] = value

    walk(cluster)
    if set(found) != {"primary", "reader"} or found["primary"] == found["reader"]:
        raise RuntimeError("Could not unambiguously identify HorizonDB primary and reader endpoints")
    return found


class Remote:
    def __init__(self, config):
        self.config = config
        self.results = Path(config["results"])
        self._journal = None

    @property
    def journal(self):
        if self._journal is None:
            fingerprint = hashlib.sha256(b"".join(
                Path(__file__).with_name(name).read_bytes()
                for name in ("worker.py", "durable.py", "setup.sh", "run_benchmark.py")
            )).hexdigest()
            self._journal = Journal(self.results / "progress.json", {
                "run_id": self.config["run_id"], "group": self.config["group"],
                "subscription": self.config["subscription"], "workload": fingerprint,
            })
        return self._journal

    def commands(self, vm):
        return infra.az("vm", "run-command", "list", "-g", self.config["group"], "--vm-name", vm)

    def sweep_commands(self, vm):
        for command in self.commands(vm):
            if not command["name"].startswith("bench-"):
                continue
            status = infra.az("rest", "--method", "get", "--url",
                              command["id"] + "?api-version=2024-11-01&$expand=instanceView")
            properties = status.get("properties", {})
            if (properties.get("instanceView", {}).get("executionState") in
                    ("Succeeded", "Failed", "TimedOut", "Canceled")
                    or properties.get("provisioningState") == "Failed"):
                self.delete_command(vm, command["name"])

    def delete_command(self, vm, name):
        infra.az("vm", "run-command", "delete", "-g", self.config["group"],
                 "--vm-name", vm, "-n", name, "--yes", cleanup=True)

    def script(self, vm, script, timeout, protected=None, *, name=None, on_terminal=None):
        existing = name is not None and any(c["name"] == name for c in self.commands(vm))
        name = name or "bench-" + secrets.token_hex(6)
        url = (
            f"https://management.azure.com/subscriptions/{self.config['subscription']}"
            f"/resourceGroups/{self.config['group']}/providers/Microsoft.Compute"
            f"/virtualMachines/{vm}/runCommands/{name}?api-version=2024-11-01"
        )
        body = {
            "location": infra.REGION,
            "properties": {
                "source": {"script": script},
                "asyncExecution": True,
                "timeoutInSeconds": timeout,
                "protectedParameters": [
                    {"name": key, "value": value}
                    for key, value in (protected or {}).items()
                ],
            },
        }
        if not existing:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as temporary:
                json.dump(body, temporary)
                temporary.flush()
                infra.az("rest", "--method", "put", "--url", url, "--body", f"@{temporary.name}")
        until = time.monotonic() + timeout + 300
        while time.monotonic() < until:
            status = infra.az(
                "rest", "--method", "get", "--url", url + "&$expand=instanceView"
            )
            view = status.get("properties", {}).get("instanceView", {})
            if view.get("executionState") in ("Succeeded", "Failed", "TimedOut", "Canceled"):
                if on_terminal:
                    on_terminal(view)
                self.delete_command(vm, name)
                return view
            if status.get("properties", {}).get("provisioningState") == "Failed":
                self.delete_command(vm, name)
                raise RuntimeError(f"VM command provisioning failed: {status}")
            time.sleep(10)
        # An interrupted controller must not remove an unobserved, still-running command.
        raise TimeoutError(f"VM command did not finish: {vm}/{name}")

    def setup(self, vm):
        self.sweep_commands(vm)
        setup = Path(__file__).with_name("setup.sh").read_text()
        fingerprint = hashlib.sha256(setup.encode()).hexdigest()
        script = (
            "#!/bin/bash\nset -euo pipefail\ninstall -d -m 700 /opt/horizon-bench\n"
            f"if [ ! -f /opt/horizon-bench/setup-{fingerprint} ]; then\n"
            + setup + f"\ntouch /opt/horizon-bench/setup-{fingerprint}\nfi\n"
        )
        for name in ("worker.py", "durable.py"):
            contents = Path(__file__).with_name(name).read_bytes()
            source = base64.b64encode(contents).decode()
            checksum = hashlib.sha256(contents).hexdigest()
            script += (
                f"if ! echo '{checksum}  /opt/horizon-bench/{name}' | sha256sum --check --status; then\n"
                "(flock -n 9 || exit 75\n"
                f"printf %s {shlex.quote(source)} | base64 -d > /opt/horizon-bench/{name}\n"
                ") 9>>/opt/horizon-bench/worker.lock\nfi\n"
            )
        script += "echo BENCH_SETUP_OK\n"
        view = self.script(vm, script, 1800, name="bench-setup-" + fingerprint[:12])
        self.save(f"setup-{vm}", view)
        if view.get("exitCode") != 0 or "BENCH_SETUP_OK" not in view.get("output", ""):
            raise RuntimeError(f"VM setup failed: {vm}: {view}")

    def save(self, name, data):
        path = self.results / f"{name}.json"
        atomic_json(path, data)

    def prepare_job(self, key, vm, operation, host, parameters):
        journal = self.journal
        signature = dict(vm=vm, operation=operation, host=host, **{
            k: v for k, v in parameters.items() if k != "timeout"
        })
        with journal.lock:
            record = journal.data["operations"].get(key)
            if record and record["signature"] != signature:
                raise RuntimeError(f"Inputs changed for checkpointed operation: {key}")
            fresh = record is None or record.get("status") == "failed"
            if fresh:
                previous = [] if record is None else [
                    *record.get("previous_attempts", []), record["job"]["job_id"],
                ]
                record = {
                    "signature": signature, "status": "pending", "previous_attempts": previous,
                    "job": dict(job_id=secrets.token_hex(8), format=FORMAT,
                                run_id=self.config["run_id"], operation=operation, host=host, **parameters),
                }
                journal.data["operations"][key] = record
                journal.save()
            return record, fresh

    def job(self, vm, operation, host, *, key, recover_only=False, **parameters):
        if not isinstance(key, str) or not key:
            raise ValueError("A stable logical job key is required")
        record, fresh = self.prepare_job(key, vm, operation, host, parameters)
        job = record["job"]
        name = "bench-work-" + job["job_id"]
        if record.get("view") and not record.get("command_retired"):
            if any(c["name"] == name for c in self.commands(vm)):
                self.delete_command(vm, name)
            with self.journal.lock:
                record["command_retired"] = True
                self.journal.save()
        artifact = self.results / f"{operation}-{job['job_id']}.json"
        if artifact.exists():
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if record.get("artifact_sha256") not in (None, digest):
                raise RuntimeError("Saved artifact checksum does not match its checkpoint")
            result = json.loads(artifact.read_text())
            return self.finish_job(record, result, key, recover_only)
        timeout = job.get("timeout", 1200 if operation != "build" else 14400)
        protected = {"DB_PASSWORD": self.config["password"], "JOB": json.dumps(job)}
        view = record.get("view")
        if view and "BENCH_FILE:" not in view.get("output", ""):
            view = None
        if not fresh and view is None and not any(c["name"] == name for c in self.commands(vm)):
            view = self.script(
                vm, "set -eu\n/usr/bin/python3 /opt/horizon-bench/worker.py --inspect\n",
                120, protected,
            )
            status = re.search(r"BENCH_STATUS:(\{.*\})", view.get("output", ""))
            if status:
                state = json.loads(status[1])["state"]
                if state == "busy":
                    raise RuntimeError(f"VM still has a live worker or orphaned child: {vm}; not starting duplicate work")
                if state not in ("absent", "interrupted"):
                    raise RuntimeError(f"Unknown worker recovery state: {state}")
                if recover_only:
                    return None
                view = None
                with self.journal.lock:
                    record.pop("view", None)
                    record["recovered_restarts"] = record.get("recovered_restarts", 0) + 1
                    self.journal.save()
        if fresh and recover_only:
            return None
        if view is None:
            def remember(value):
                with self.journal.lock:
                    record["view"] = value
                    record["command_retired"] = False
                    self.journal.save()
            view = self.script(
                vm, "set -eu\n/usr/bin/python3 /opt/horizon-bench/worker.py\n",
                timeout, protected, name=name, on_terminal=remember,
            )
            with self.journal.lock:
                record["command_retired"] = True
                self.journal.save()
        output = view.get("output", "")
        metadata = re.search(r"BENCH_FILE:([a-f0-9]+\.b64):(\d+):([a-f0-9]{64})", output)
        if not metadata or metadata[1] != f"{job['job_id']}.b64":
            self.save(f"failed-{job['job_id']}", {"job": job, "instance_view": view})
            with self.journal.lock:
                record["status"] = "failed"
                self.journal.save()
            if recover_only:
                return None
            raise RuntimeError(f"VM command did not return a benchmark artifact: {view}")
        inline = re.search(r"BENCH_DATA:([A-Za-z0-9+/=]+)", output)
        if inline:
            encoded = inline[1]
        else:
            chunks = []
            for offset in range(0, int(metadata[2]), 3500):
                fetch = self.script(
                    vm,
                    "python3 -c 'from pathlib import Path; "
                    f'print("BENCH_CHUNK:"+Path("/opt/horizon-bench/{metadata[1]}")'
                    f".read_text()[{offset}:{offset + 3500}])'\n",
                    120,
                )
                match = re.search(r"BENCH_CHUNK:([A-Za-z0-9+/=]+)", fetch.get("output", ""))
                if fetch.get("exitCode") != 0 or not match:
                    raise RuntimeError(f"Could not retrieve complete benchmark artifact: {fetch}")
                chunks.append(match[1])
            encoded = "".join(chunks)
        if (
            len(encoded) != int(metadata[2])
            or hashlib.sha256(encoded.encode()).hexdigest() != metadata[3]
        ):
            raise RuntimeError("Downloaded artifact checksum does not match the VM result")
        result = decode_result(encoded)
        if result["job"] != job:
            raise RuntimeError("Downloaded artifact belongs to a different benchmark job")
        if view.get("exitCode") != 0 and result["ok"]:
            raise RuntimeError("VM command failed despite a success-shaped artifact")
        name = f"{operation}-{job['job_id']}"
        self.save(name, result)
        with self.journal.lock:
            record["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.journal.save()
        print(json.dumps({
            "artifact": name, "operation": operation, "vm": vm,
            "ok": result["ok"], "warehouses": job.get("warehouses"),
            "users": job.get("users"), "nopm": result.get("result", {}).get("nopm"),
        }), flush=True)
        return self.finish_job(record, result, key, recover_only)

    def finish_job(self, record, result, key, recover_only):
        if result["job"] != record["job"]:
            raise RuntimeError(f"Saved artifact does not match the checkpointed job: {key}")
        with self.journal.lock:
            record["status"] = "completed" if result["ok"] else "failed"
            path = self.results / f"{record['job']['operation']}-{record['job']['job_id']}.json"
            record.setdefault("artifact_sha256", hashlib.sha256(path.read_bytes()).hexdigest())
            self.journal.save()
        if not result["ok"]:
            if recover_only:
                return None
            raise RuntimeError(f"Benchmark failed; details in {record['job']['job_id']}: {result.get('error')}")
        return result["result"]

    def dataset_id(self, key):
        return hashlib.sha256(f"{self.config['run_id']}:{key}".encode()).hexdigest()[:16]

    def recover_pending(self):
        def recover(vm):
            names = {command["name"] for command in self.commands(vm)}
            pending = [
                (key, record) for key, record in list(self.journal.data["operations"].items())
                if record["status"] == "pending" and record["signature"]["vm"] == vm
            ]
            pending.sort(key=lambda item: "bench-work-" + item[1]["job"]["job_id"] not in names)
            for key, record in pending:
                signature = dict(record["signature"])
                parameters = {k: v for k, v in record["job"].items()
                              if k not in ("job_id", "format", "run_id", "operation", "host")}
                result = self.job(signature["vm"], signature["operation"], signature["host"],
                                  key=key, recover_only=True, **parameters)
                if result is None:
                    with self.journal.lock:
                        if record["status"] == "pending":
                            record["status"] = "interrupted"
                        self.journal.save()
        parallel(recover, self.config["client_vms"])

    def validate(self, target, dataset_id, warehouses):
        return self.job(
            target["vm"], "validate", target["host"], key="validate/" + secrets.token_hex(8),
            dataset_id=dataset_id, warehouses=warehouses,
        )

    def distributed(self, key, target, warehouses, dataset_id, peak):
        journal = self.journal
        pair = journal.data["pairs"].get(key)
        clients = [(self.config["client_vms"][0], peak // 2),
                   (self.config["client_vms"][1], peak - peak // 2)]

        def run(part, recover_only=False):
            index, (vm, count) = part
            return self.job(
                vm, "measure", target["host"], key=f"{key}/{pair['attempt']}/{index}",
                recover_only=recover_only, warehouses=warehouses, dataset_id=dataset_id,
                users=count, start_at=pair["start_at"],
            )

        def validate(results):
            spread = abs(results[0]["started_epoch"] - results[1]["started_epoch"])
            if spread > 2:
                pair["status"] = "invalid_start_skew"
                journal.save()
                raise RuntimeError("Distributed driver start times differed by over two seconds")
            return results

        if pair and pair.get("status") != "invalid_start_skew":
            recovered = parallel(lambda part: run(part, True), list(enumerate(clients)))
            if all(result is not None for result in recovered):
                return validate(recovered)
        if pair:
            for index in range(2):
                old = journal.data["operations"].get(f"{key}/{pair['attempt']}/{index}")
                if old:
                    old["pair_disposition"] = "superseded; incomplete pair or invalid start skew"
        pair = {"attempt": 0 if pair is None else pair["attempt"] + 1, "start_at": time.time() + 120}
        journal.data["pairs"][key] = pair
        # Commit both identities before either half can start.
        for index, (vm, count) in enumerate(clients):
            self.prepare_job(f"{key}/{pair['attempt']}/{index}", vm, "measure", target["host"], {
                "warehouses": warehouses, "dataset_id": dataset_id, "users": count,
                "start_at": pair["start_at"],
            })
        journal.save()
        return validate(parallel(run, list(enumerate(clients))))


def parallel(function, items):
    with ThreadPoolExecutor(max_workers=2) as executor:
        return list(executor.map(function, items))


def preflight():
    config = json.loads(os.environ["BENCH_CONFIG"])
    infra.DEADLINE = time.monotonic() + config["deadline_epoch"] - time.time()
    remote = Remote(config)

    def check(vm):
        remote.sweep_commands(vm)
        encoded = base64.b64encode(os.urandom(2625)).decode()
        checksum = hashlib.sha256(encoded.encode()).hexdigest()
        expected = (
            f"BENCH_FILE:0000000000000000.b64:{len(encoded)}:{checksum}\n"
            f"BENCH_DATA:{encoded}"
        )
        view = remote.script(vm, f"printf '%s\\n' {shlex.quote(expected)}\n", 120)
        remote.save(f"transport-preflight-{vm}", view)
        if view.get("exitCode") != 0 or expected not in view.get("output", ""):
            raise RuntimeError(f"Management API result transport failed: {vm}")
        commands = infra.az(
            "vm", "run-command", "list", "-g", config["group"], "--vm-name", vm,
        )
        if any(command["name"].startswith("bench-") for command in commands):
            raise RuntimeError(f"Completed benchmark command was not deleted: {vm}")

    parallel(check, config["client_vms"])
    print("Result transport and command deletion completed on both VMs", flush=True)


def capture_metrics(remote, resources, start):
    for label, resource in resources.items():
        definitions = infra.az("monitor", "metrics", "list-definitions", "--resource", resource["id"])
        remote.save(f"metric-definitions-{label}", definitions)
        selected = [
            item for item in definitions
            if re.search(
                r"cpu|memory|iops|throughput|cache|replica.*lag|connections",
                item["name"]["value"], re.I,
            )
        ]
        for index in range(0, len(selected), 10):
            batch = selected[index:index + 10]
            common = set.intersection(*(
                {availability["timeGrain"] for availability in item["metricAvailabilities"]}
                for item in batch
            ))
            interval = next((grain for grain in (
                "PT1M", "PT5M", "PT15M", "PT30M", "PT1H", "PT6H", "PT12H", "P1D",
            ) if grain in common), None)
            if interval is None:
                raise RuntimeError(f"No supported common metrics interval for {label}")
            metrics = infra.az(
                "monitor", "metrics", "list", "--resource", resource["id"],
                "--metric", *(item["name"]["value"] for item in batch), "--interval", interval,
                "--start-time", start, "--end-time",
                dt.datetime.now(dt.timezone.utc).isoformat(),
            )
            remote.save(f"metrics-{label}-{index}", metrics)


def write_csv(remote, manifest):
    rows = [row for stage in manifest["stages"] for row in stage.get("rows", [])]
    if rows:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        atomic_text(remote.results / "tprocc.csv", stream.getvalue())


def main():
    config = json.loads(os.environ["BENCH_CONFIG"])
    infra.DEADLINE = time.monotonic() + config["deadline_epoch"] - time.time()
    infra.REDACTIONS.append(config["password"])
    remote = Remote(config)
    remote.journal
    manifest_path = remote.results / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {
        "format": FORMAT, "stages": [], "status": "running",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "method": "HammerDB 6.1 TPROC-C, 2-minute ramp, 5-minute timed interval, 3 repeats",
        "limits": "Explicit execution window; expiry pauses clients, retains DBs; not a hard billing cap",
        "distributed_nopm": "Global database counter from VM1 only; never sum the two monitors",
        "supplement": "Rate-limited pgbench on TPROC-C data; not part of TPROC-C score",
        "driver": "Active-user count verified; wait for vucomplete before export and destruction",
        "timing_window": "HammerDB time profiles include rampup and measurement",
    }
    if manifest.get("format") != FORMAT:
        raise RuntimeError("Legacy measurements cannot be resumed")
    if manifest["status"] == "completed":
        write_csv(remote, manifest)
        return
    started = manifest["started_utc"]
    manifest["status"] = "running"
    manifest.pop("error", None)
    remote.save("manifest", manifest)
    write_csv(remote, manifest)
    resources = {
        "horizon": infra.az("horizondb", "show", "-g", config["group"], "-n", config["horizon"]),
        "flexible": infra.az(
            "postgres", "flexible-server", "show", "-g", config["group"], "-n", config["flexible"]
        ),
        "flexible_replica": infra.az(
            "postgres", "flexible-server", "show", "-g", config["group"],
            "-n", config["flexible_replica"],
        ),
    }
    remote.save("azure-resources", resources)
    horizon_properties = resources["horizon"]["properties"]
    if horizon_properties["vCores"] != 8 or horizon_properties["replicaCount"] != 2:
        raise RuntimeError("HorizonDB must have exactly two 8-vCore compute replicas")
    for label in ("flexible", "flexible_replica"):
        if resources[label]["sku"]["name"] != "Standard_E8ds_v5":
            raise RuntimeError(f"{label} did not receive the requested 8-vCore SKU")
    horizon = endpoints(resources["horizon"])
    targets = [
        {
            "label": "horizon", "vm": config["client_vms"][0],
            "host": horizon["primary"], "replica": horizon["reader"],
        },
        {
            "label": "flexible", "vm": config["client_vms"][1],
            "host": resources["flexible"]["fullyQualifiedDomainName"],
            "replica": resources["flexible_replica"]["fullyQualifiedDomainName"],
        },
    ]
    parallel(remote.setup, config["client_vms"])
    remote.recover_pending()
    session_id = secrets.token_hex(8)
    metadata = parallel(lambda t: remote.job(
        t["vm"], "metadata", t["host"], key=f"metadata/{session_id}/{t['label']}"
    ), targets)
    remote.save("metadata", dict(zip(("horizon", "flexible"), metadata)))
    for target, data in zip(targets, metadata):
        settings = {setting["name"]: setting["setting"] for setting in data["settings"]}
        if int(settings["max_connections"]) < max(USERS) + 20:
            raise RuntimeError(f"{target['label']} has insufficient max_connections")
        if settings["synchronous_commit"] != "on" or settings["fsync"] != "on":
            raise RuntimeError("Durability settings are not equivalent")
    dataset_ids = {t["label"]: remote.dataset_id(f"calibration/{t['label']}") for t in targets}
    if "calibration" not in manifest:
        calibration = parallel(lambda t: remote.job(
            t["vm"], "build", t["host"], key=f"calibration/{t['label']}",
            warehouses=10, dataset_id=dataset_ids[t["label"]], previous_dataset=None,
        ), targets)
        parallel(lambda t: remote.validate(t, dataset_ids[t["label"]], 10), targets)
        parallel(lambda t: remote.job(
            t["vm"], "measure", t["host"], key=f"trial/{t['label']}", warehouses=10,
            users=1, dataset_id=dataset_ids[t["label"]],
        ), targets)
        parallel(lambda t: remote.job(
            t["vm"], "replica", t["host"], key=f"calibration-replica/{t['label']}",
            replica=t["replica"], timeout=2100,
        ), targets)
        manifest["calibration"] = calibration
        remote.save("manifest", manifest)
    calibration = manifest["calibration"]
    sizes = [result["database"]["sizes"] for result in calibration]
    for gib in STAGES:
        stage = next((s for s in manifest["stages"] if s["target_gib"] == gib), None)
        if stage and stage["status"] == "completed":
            calibration = stage["built"]
            sizes = stage["measured_sizes"]
            dataset_ids = stage["dataset_ids"]
            continue
        warehouses = warehouse_count(gib * 2**30, sizes)
        previous_ids = dataset_ids
        dataset_ids = {t["label"]: remote.dataset_id(f"{gib}/build/{t['label']}") for t in targets}
        if stage is None:
            stage = {
                "target_gib": gib, "warehouses": warehouses, "status": "running",
                "dataset_ids": dataset_ids, "rows": [], "distributed_client_checks": {},
                "supplemental_runs": [],
            }
            manifest["stages"].append(stage)
        if stage["warehouses"] != warehouses or stage["dataset_ids"] != dataset_ids:
            raise RuntimeError("Stage inputs differ from the checkpoint")
        stage["status"] = "running"
        remote.save("manifest", manifest)
        build_seconds = max(
            item["ended_epoch"] - item["started_epoch"] for item in calibration
        ) * warehouses / calibration[0]["database"]["sizes"]["warehouses"]
        users = USERS if gib < 1024 else (16, 64, 256)

        def completed(key):
            return remote.journal.data["operations"].get(key, {}).get("status") == "completed"
        pending = sum(
            not all(completed(f"{gib}/measure/{repeat}/{count}/{t['label']}") for t in targets)
            for repeat in range(1, 4) for count in users
        )
        measurement_seconds = pending * 480 + (2 - len(stage["distributed_client_checks"])) * 1320 + 2400
        if gib == 250:
            measurement_seconds += (12 - len(stage["supplemental_runs"])) * 240
        needed = (0 if all(completed(f"{gib}/build/{t['label']}") for t in targets) else build_seconds) + measurement_seconds
        remaining = config["deadline_epoch"] - time.time()
        if remaining < needed:
            stage.update(status="paused", reason="Insufficient execution window for unfinished work",
                         estimated_seconds=needed, remaining_seconds=remaining)
            manifest["status"] = "incomplete"
            remote.save("manifest", manifest)
            raise TimeoutError(f"Cannot safely complete the {gib} GiB stage within the time limit")
        built = parallel(
            lambda t: remote.job(
                t["vm"], "build", t["host"], warehouses=warehouses,
                timeout=max(1, int(remaining - measurement_seconds)),
                key=f"{gib}/build/{t['label']}", dataset_id=dataset_ids[t["label"]],
                previous_dataset=previous_ids[t["label"]],
            ),
            targets,
        )
        stage["built"] = built
        stage["measured_sizes"] = [result["database"]["sizes"] for result in built]
        parallel(lambda t: remote.validate(t, dataset_ids[t["label"]], warehouses), targets)
        remote.save("manifest", manifest)
        for result in built:
            actual = result["database"]["sizes"]["data_bytes"]
            if abs(actual / (gib * 2**30) - 1) > .10:
                raise RuntimeError(f"Measured data size {actual} is outside +/-10% of {gib} GiB")
        parallel(
            lambda t: remote.job(
                t["vm"], "replica", t["host"], replica=t["replica"], timeout=2100,
                key=f"{gib}/replica/{t['label']}",
            ),
            targets,
        )
        for repeat in range(1, 4):
            order = users if repeat % 2 else tuple(reversed(users))
            for count in order:
                results = parallel(
                    lambda t: remote.job(
                        t["vm"], "measure", t["host"], warehouses=warehouses, users=count,
                        key=f"{gib}/measure/{repeat}/{count}/{t['label']}",
                        dataset_id=dataset_ids[t["label"]],
                    ),
                    targets,
                )
                for target, result in zip(targets, results):
                    growth = (
                        result["after"]["sizes"]["data_bytes"]
                        / result["before"]["sizes"]["data_bytes"] - 1
                    )
                    stage["rows"] = [
                        row for row in stage["rows"]
                        if (row["service"], row["active_users"], row["repeat"]) != (target["label"], count, repeat)
                    ]
                    stage["rows"].append({
                        "service": target["label"], "target_gib": gib,
                        "warehouses": warehouses, "active_users": count, "repeat": repeat,
                        "nopm": result["nopm"], "tpm": result["tpm"],
                        "data_growth_fraction": growth, **result["telemetry"],
                    })
                remote.save("manifest", manifest)
                write_csv(remote, manifest)
        for target in targets:
            if target["label"] in stage["distributed_client_checks"]:
                continue
            service_rows = [
                row for row in stage["rows"] if row["service"] == target["label"]
            ]
            peak = max(
                users,
                key=lambda n: statistics.median(
                    row["nopm"] for row in service_rows if row["active_users"] == n
                ),
            )
            baseline = statistics.median(
                row["nopm"] for row in service_rows if row["active_users"] == peak
            )
            if peak == 1:
                stage["distributed_client_checks"][target["label"]] = {
                    "status": "not_applicable", "reason": "Peak concurrency is one user"
                }
                remote.save("manifest", manifest)
                continue
            split = remote.distributed(
                f"{gib}/distributed/{target['label']}", target, warehouses,
                dataset_ids[target["label"]], peak,
            )
            spread = abs(split[0]["started_epoch"] - split[1]["started_epoch"])
            if spread > 2:
                raise RuntimeError("Distributed driver start times differed by over two seconds")
            stage["distributed_client_checks"][target["label"]] = {
                "active_users": peak, "single_client_median_nopm": baseline,
                "two_client_global_nopm": split[0]["nopm"],
                "throughput_ratio": split[0]["nopm"] / baseline if baseline else None,
                "start_spread_seconds": spread,
                "client_telemetry": [result["telemetry"] for result in split],
                "note": "One two-client sample; database-global NOPM is not additive",
            }
            remote.save("manifest", manifest)
        if gib == 250:
            for read_percent in (80, 50):
                for connections in (20, 80, 160):
                    for route in ("primary", "replica"):
                        if any((r["read_percent"], r["total_connections"], r["route"]) ==
                               (read_percent, connections, route) for r in stage["supplemental_runs"]):
                            continue
                        read_clients = connections * read_percent // 100
                        values = parallel(
                            lambda t: remote.job(
                                t["vm"], "supplement", t["host"], warehouses=warehouses,
                                reader=t["host"] if route == "primary" else t["replica"],
                                replica=t["replica"], read_clients=read_clients,
                                write_clients=connections - read_clients,
                                read_rate=1000 * read_percent // 100,
                                write_rate=1000 * (100 - read_percent) // 100,
                                dataset_id=dataset_ids[t["label"]],
                                key=f"{gib}/supplement/{read_percent}/{connections}/{route}/{t['label']}",
                            ),
                            targets,
                        )
                        stage["supplemental_runs"].append({
                            "read_percent": read_percent, "total_connections": connections,
                            "route": route, "offered_transactions_per_second": 1000,
                            "results": dict(zip(("horizon", "flexible"), values)),
                        })
                        remote.save("manifest", manifest)
        stage["status"] = "completed"
        calibration = built
        sizes = [result["database"]["sizes"] for result in built]
        remote.save("manifest", manifest)
    capture_metrics(remote, resources, started)
    manifest["status"] = "completed"
    remote.save("manifest", manifest)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--preflight"]:
            preflight()
        elif sys.argv[1:]:
            raise SystemExit("Usage: run_benchmark.py [--preflight]")
        else:
            main()
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        config = json.loads(os.environ["BENCH_CONFIG"])
        path = Path(config["results"]) / "manifest.json"
        manifest = json.loads(path.read_text()) if path.exists() else {}
        if manifest.get("status") != "incomplete":
            manifest["status"] = "paused"
        for stage in manifest.get("stages", []):
            if stage["status"] == "running":
                stage["status"] = "paused"
        message = str(error)
        if "password" in config:
            message = message.replace(config["password"], "<redacted>")
        manifest["error"] = message
        atomic_json(path, manifest)
        raise
