"""VM-side benchmark operations. Credentials arrive as protected Run Command input."""

import base64
from contextlib import closing
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import threading
import time
import traceback
import zlib

from durable import FORMAT, atomic_json, atomic_text

ROOT = Path("/opt/horizon-bench")
HAMMER = ROOT / "HammerDB-6.1"
PGBENCH = "/usr/lib/postgresql/17/bin/pgbench"
LOCK_FD = None


def inherited_lock():
    # Children retain the lock even if Run Command kills only the Python parent.
    return {"pass_fds": (LOCK_FD,)} if LOCK_FD is not None else {}


def connect(host, database="tprocc"):
    import psycopg2

    connection = psycopg2.connect(
        host=host, dbname=database, user="benchadmin",
        password=os.environ["DB_PASSWORD"], sslmode="verify-full",
        sslrootcert="/etc/ssl/certs/ca-certificates.crt",
        connect_timeout=30, application_name="horizon-benchmark",
    )
    connection.autocommit = True
    return connection


def query(host, sql, database="tprocc"):
    with closing(connect(host, database)) as connection, connection.cursor() as cursor:
        cursor.execute(sql)
        columns = [column.name for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def database_state(host):
    return {
        "sizes": query(host, """
            SELECT pg_database_size(current_database()) AS database_bytes,
                (SELECT sum(pg_total_relation_size(c.oid))
                 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='public' AND c.relkind IN ('r','m'))::bigint AS data_bytes,
                (SELECT count(*) FROM warehouse) AS warehouses,
                (SELECT sum(d_next_o_id)::bigint FROM district) AS next_order_sum
        """)[0],
        "stats": query(host, """
            SELECT xact_commit,xact_rollback,blks_read,blks_hit,
                   tup_inserted,tup_updated,tup_deleted,temp_bytes,deadlocks
            FROM pg_stat_database WHERE datname=current_database()
        """)[0],
    }


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


class Telemetry:
    def __init__(self):
        self.stop_event = threading.Event()
        self.samples = []
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.error = None

    @staticmethod
    def snapshot():
        cpu = {}
        for line in Path("/proc/stat").read_text().splitlines():
            fields = line.split()
            if fields[0].startswith("cpu"):
                values = [int(value) for value in fields[1:9]]
                cpu[fields[0]] = (sum(values), values[3] + values[4])
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.split()[0])
        network = 0
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            interface, values = line.split(":")
            if interface.strip() != "lo":
                fields = values.split()
                network += int(fields[0]) + int(fields[8])
        return cpu, memory, network

    def collect(self):
        try:
            previous, _, network_before = self.snapshot()
            while not self.stop_event.wait(5):
                current, memory, network = self.snapshot()
                busy = {}
                for key, (total, idle) in current.items():
                    old_total, old_idle = previous[key]
                    delta = total - old_total
                    busy[key] = 100 * (1 - (idle - old_idle) / delta) if delta else 0
                self.samples.append({
                    "epoch": time.time(), "cpu_percent": busy["cpu"],
                    "busiest_core_percent": max(v for k, v in busy.items() if k != "cpu"),
                    "memory_available_percent": 100 * memory["MemAvailable"] / memory["MemTotal"],
                    "network_bytes_per_second": (network - network_before) / 5,
                })
                previous, network_before = current, network
        except Exception as error:
            self.error = error

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join()
        if self.error:
            raise RuntimeError("Client telemetry collection failed") from self.error

    def summary(self, since, until=None):
        samples = [
            sample for sample in self.samples
            if sample["epoch"] >= since and (until is None or sample["epoch"] <= until)
        ]
        if not samples:
            raise RuntimeError("No client telemetry samples in the measurement window")
        cpu = percentile([s["cpu_percent"] for s in samples], .95)
        core = percentile([s["busiest_core_percent"] for s in samples], .95)
        memory = min(s["memory_available_percent"] for s in samples)
        return {
            "cpu_p95_percent": cpu, "busiest_core_p95_percent": core,
            "memory_available_min_percent": memory,
            "network_peak_bytes_per_second": max(s["network_bytes_per_second"] for s in samples),
            "possible_client_limit": cpu >= 70 or core >= 85 or memory < 20,
        }


def hammer_script(host, warehouses, *, users=None):
    lines = [
        "dbset db pg", "dbset bm TPC-C",
        f"diset connection pg_host {host}",
        "diset connection pg_port 5432",
        "diset connection pg_sslmode verify-full",
        "diset tpcc pg_superuser benchadmin",
        "diset tpcc pg_superuserpass $::env(DB_PASSWORD)",
        "diset tpcc pg_defaultdbase postgres",
        "diset tpcc pg_user benchadmin",
        "diset tpcc pg_pass $::env(DB_PASSWORD)",
        "diset tpcc pg_dbase tprocc",
        f"diset tpcc pg_count_ware {warehouses}",
        "diset tpcc pg_storedprocs true",
        "diset tpcc pg_partition true",
    ]
    if users is None:
        lines += [f"diset tpcc pg_num_vu {min(16, warehouses)}", "buildschema"]
    else:
        lines += [
            "diset tpcc pg_driver timed", "diset tpcc pg_rampup 2",
            "diset tpcc pg_duration 5", "diset tpcc pg_raiseerror true",
            "diset tpcc pg_total_iterations 2147483647",
            "diset tpcc pg_keyandthink false", "diset tpcc pg_allwarehouse true",
            "diset tpcc pg_timeprofile true", "diset tpcc pg_vacuum false",
            "loadscript", f"vuset vu {users}", "vuset delay 0", "vuset logtotemp 1",
            "vucreate", "set jobid [lindex [split [vurun] =] end]",
            "set finish_deadline [expr {[clock milliseconds] + 600000}]",
            "while {![vucomplete]} {",
            "    if {[clock milliseconds] >= $finish_deadline} {",
            '        error "Timed out waiting for HammerDB virtual users to complete"',
            "    }",
            "    after 1000",
            "    update",
            "}",
            'puts "BENCHMARK_TIMING"', "job $jobid timing",
            'puts "BENCHMARK_RESULT"', "job $jobid result", "vudestroy",
        ]
    return "\n".join(lines) + "\n"


def build_log_excerpt(log):
    lines = log.splitlines(keepends=True)
    if len(lines) <= 100:
        return log, 0
    omitted = len(lines) - 100
    excerpt = (
        "".join(lines[:50]) + f"\n[{omitted} build progress lines omitted]\n"
        + "".join(lines[-50:])
    )
    return excerpt, omitted


def measurement_result(log, users):
    created = re.findall(r"(?m)^(\d+) Virtual Users Created with Monitor VU\s*$", log)
    active = re.findall(r"(?m)^Vuser 1:(\d+) Active Virtual Users configured\s*$", log)
    if created != [str(users + 1)] or active != [str(users)]:
        raise RuntimeError(f"HammerDB virtual-user count does not match {users} active users:\n{log}")
    if "ALL VIRTUAL USERS COMPLETE" not in log:
        raise RuntimeError(f"HammerDB virtual users did not complete:\n{log}")
    finished = sorted(map(int, re.findall(
        r"(?m)^Vuser (\d+):FINISHED SUCCESS\s*$", log
    )))
    if finished != list(range(1, users + 2)) or re.search(
        r"FINISHED FAILED|Error in Virtual User|Timing Data Incomplete|Timing Gather Timed Out", log
    ):
        raise RuntimeError(f"HammerDB virtual-user execution or timing gather failed:\n{log}")
    matches = re.findall(r"(\d+)\s+NOPM\s+from\s+(\d+)\s+PostgreSQL\s+TPM", log, flags=re.I)
    if not matches:
        raise RuntimeError(f"HammerDB did not produce NOPM/TPM:\n{log}")
    timing = re.search(r"BENCHMARK_TIMING\s*\n(.*?)\nBENCHMARK_RESULT", log, re.S)
    if not timing:
        raise RuntimeError(f"HammerDB did not export transaction timings:\n{log}")
    try:
        timings = json.loads(timing[1])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"HammerDB transaction timings are not valid JSON:\n{log}") from error
    if not isinstance(timings, dict) or set(timings) != {
        "NEWORD", "PAYMENT", "DELIVERY", "SLEV", "OSTAT",
    }:
        raise RuntimeError(f"HammerDB transaction timings are incomplete:\n{log}")
    for name, values in timings.items():
        if not isinstance(values, dict) or not {"calls", "p95_ms", "p99_ms"} <= values.keys():
            raise RuntimeError(f"HammerDB {name} transaction timing fields are missing:\n{log}")
        try:
            calls = int(values["calls"])
            p95, p99 = float(values["p95_ms"]), float(values["p99_ms"])
        except (TypeError, ValueError) as error:
            raise RuntimeError(f"HammerDB {name} timing values are not numeric:\n{log}") from error
        if (
            calls <= 0 or not math.isfinite(p95) or not math.isfinite(p99)
            or not 0 <= p95 <= p99
        ):
            raise RuntimeError(f"HammerDB {name} transaction timings are invalid:\n{log}")
    return {
        "nopm": int(matches[-1][0]), "tpm": int(matches[-1][1]),
        "active_users": int(active[0]), "monitor_users": 1, "timings": timings,
        "timing_window": "rampup_and_measurement",
    }


def ensure_open_file_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    required = 65536
    if soft != resource.RLIM_INFINITY and soft < required:
        if hard != resource.RLIM_INFINITY and hard < required:
            raise RuntimeError(f"HammerDB requires an open-file limit of {required}; hard limit is {hard}")
        resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
        soft = required
    return soft


def run_hammer(job, users=None):
    # Each Tcl virtual user opens notifier, SQLite and PostgreSQL descriptors.
    open_file_limit = ensure_open_file_limit()
    work = ROOT / job["job_id"]
    work.mkdir(exist_ok=True)
    script = work / "run.tcl"
    script.write_text(hammer_script(job["host"], job["warehouses"], users=users))
    environment = dict(
        os.environ, TMP=str(work), PGSSLROOTCERT="/etc/ssl/certs/ca-certificates.crt"
    )
    start_at = job.get("start_at", time.time())
    if start_at < time.time() - 5:
        raise RuntimeError("Missed synchronized benchmark start")
    time.sleep(max(0, start_at - time.time()))
    started = time.time()
    with Telemetry() as telemetry:
        process = subprocess.run(
            [str(HAMMER / "hammerdbcli"), "auto", str(script)],
            cwd=HAMMER, env=environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=job.get("timeout", 14400 if users is None else 1200),
            **inherited_lock(),
        )
    log = process.stdout.replace(os.environ["DB_PASSWORD"], "<redacted>")
    (work / "hammerdb.log").write_text(log)
    if process.returncode:
        raise RuntimeError(f"HammerDB exited {process.returncode}:\n{log}")
    if re.search(r"(?im)^(?:Error:|.*VU.*:Error|FATAL:|.*failed to connect)", log):
        raise RuntimeError(f"HammerDB reported an execution error:\n{log}")
    result = {
        "log": log, "started_epoch": started, "ended_epoch": time.time(),
        "open_file_soft_limit": open_file_limit,
        "telemetry": telemetry.summary(
            started + (120 if users is not None else 0),
            started + 420 if users is not None else None,
        ),
        "log_omitted_lines": 0,
        "full_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
    }
    if users is None:
        if "SCHEMA COMPLETE" not in log:
            raise RuntimeError(f"HammerDB did not confirm schema completion:\n{log}")
        result["log"], result["log_omitted_lines"] = build_log_excerpt(log)
    else:
        result.update(measurement_result(log, users))
    return result


def dataset_marker(host):
    if not query(host, "SELECT 1 FROM pg_database WHERE datname='tprocc'", "postgres"):
        return None, False
    if not query(host, "SELECT to_regclass('bench_control.dataset') AS relation")[0]["relation"]:
        return None, True
    return query(host, "SELECT run_id,dataset_id,warehouses,result FROM bench_control.dataset")[0], True


def validate_dataset(job):
    marker, _ = dataset_marker(job["host"])
    if not marker or any(marker[k] != job[k] for k in ("run_id", "dataset_id", "warehouses")):
        raise RuntimeError("Live database does not match the completed dataset checkpoint")
    actual = database_state(job["host"])
    if actual["sizes"]["warehouses"] != job["warehouses"]:
        raise RuntimeError("Live warehouse count does not match the dataset marker")
    return actual


def build(job):
    marker, exists = dataset_marker(job["host"])
    if marker:
        if marker["run_id"] == job["run_id"] and marker["dataset_id"] == job["dataset_id"]:
            validate_dataset(job)
            return marker["result"]
        if marker["run_id"] != job["run_id"] or marker["dataset_id"] != job.get("previous_dataset"):
            raise RuntimeError("Refusing to replace a completed dataset with an unexpected identity")
    intent = ROOT / ("build-" + hashlib.sha256(job["host"].encode()).hexdigest()[:16] + ".json")
    identity = {key: job[key] for key in ("host", "run_id", "dataset_id", "warehouses")}
    if exists and not marker:
        if not intent.exists() or json.loads(intent.read_text()) != identity:
            raise RuntimeError("Refusing to drop an unmarked database without this build's durable intent")
    atomic_json(intent, identity)
    with closing(connect(job["host"], "postgres")) as connection, connection.cursor() as cursor:
        cursor.execute("DROP DATABASE IF EXISTS tprocc WITH (FORCE)")
    result = run_hammer(job)
    result["database"] = database_state(job["host"])
    if result["database"]["sizes"]["warehouses"] != job["warehouses"]:
        raise RuntimeError("Built warehouse count does not match requested count")
    with closing(connect(job["host"])) as connection, connection.cursor() as cursor:
        connection.autocommit = False
        cursor.execute("CREATE SCHEMA bench_control")
        cursor.execute("CREATE TABLE bench_control.probe (id int PRIMARY KEY, value bigint)")
        cursor.execute("INSERT INTO bench_control.probe VALUES (1,0)")
        cursor.execute("""
            CREATE TABLE bench_control.dataset (
                run_id text NOT NULL, dataset_id text PRIMARY KEY,
                warehouses bigint NOT NULL, result jsonb NOT NULL
            )
        """)
        cursor.execute(
            "INSERT INTO bench_control.dataset VALUES (%s,%s,%s,%s::jsonb)",
            (job["run_id"], job["dataset_id"], job["warehouses"], json.dumps(result, default=str)),
        )
        connection.commit()
    return result


def metadata(job):
    host = job["host"]
    settings = query(host, """
        SELECT name,setting,unit FROM pg_settings WHERE name IN
        ('server_version','max_connections','shared_buffers','work_mem',
         'maintenance_work_mem','effective_cache_size','synchronous_commit',
         'full_page_writes','fsync','jit','max_wal_size','checkpoint_timeout',
         'autovacuum','default_transaction_isolation','default_transaction_read_only')
        ORDER BY name
    """, "postgres")
    return {
        "postgres": query(host, "SELECT version()", "postgres"),
        "settings": settings,
        "cpu": subprocess.check_output(["lscpu"], text=True),
        "perf_event_paranoid": Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip(),
        "pgbench_version": subprocess.check_output([PGBENCH, "--version"], text=True).strip(),
    }


def measure(job):
    validate_dataset(job)
    before = database_state(job["host"])
    result = run_hammer(job, job["users"])
    result.update(before=before, after=database_state(job["host"]))
    return result


def replica_probe(primary, reader, timeout=300):
    import psycopg2

    sequence = time.time_ns()
    with closing(connect(primary)) as writer, writer.cursor() as cursor:
        cursor.execute("UPDATE bench_control.probe SET value=%s WHERE id=1", (sequence,))
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            with closing(connect(reader)) as replica, replica.cursor() as cursor:
                cursor.execute("SHOW transaction_read_only")
                if cursor.fetchone()[0] != "on":
                    raise RuntimeError("Reader endpoint is not read-only")
                while time.monotonic() - started < timeout:
                    cursor.execute("SELECT value FROM bench_control.probe WHERE id=1")
                    row = cursor.fetchone()
                    if row and row[0] == sequence:
                        return time.monotonic() - started
                    time.sleep(.05)
        except psycopg2.Error as error:
            if error.pgcode not in ("42P01", "3F000", "57P01", "57P04", "3D000"):
                raise
            print(f"Replica schema is not ready (SQLSTATE {error.pgcode}); retrying", flush=True)
            time.sleep(1)
    raise TimeoutError(f"Replica did not observe the committed probe within {timeout} seconds")


def supplement(job):
    validate_dataset(job)
    host = job["host"]
    work = ROOT / job["job_id"]
    work.mkdir(exist_ok=True)
    prefix = (
        f"\\set w random(1,{job['warehouses']})\n"
        "\\set d random(1,10)\n\\set c random(1,3000)\n"
    )
    scripts = {
        "read": prefix + (
            "SELECT c_balance,c_ytd_payment FROM customer "
            "WHERE c_w_id=:w AND c_d_id=:d AND c_id=:c;\n"
        ),
        "write": prefix + (
            "BEGIN;\nUPDATE customer SET c_balance=c_balance+0.01 "
            "WHERE c_w_id=:w AND c_d_id=:d AND c_id=:c;\nCOMMIT;\n"
        ),
    }
    commands = []
    for kind, count, rate in (
        ("read", job["read_clients"], job["read_rate"]),
        ("write", job["write_clients"], job["write_rate"]),
    ):
        script = work / f"{kind}.sql"
        script.write_text(scripts[kind])
        command = [
            PGBENCH, "-n", "-h", job["reader"] if kind == "read" else host,
            "-U", "benchadmin", "-d", "tprocc", "-c", str(count),
            "-j", str(min(count, 16)), "-T", "180", "-P", "30",
            "-M", "prepared", "-f", str(script), "-R", str(rate),
            "-L", "1000", "-l", "--sampling-rate=0.01",
            f"--log-prefix={work / kind}",
            "--random-seed=20261023",
        ]
        commands.append((kind, command))
    environment = dict(
        os.environ, PGPASSWORD=os.environ["DB_PASSWORD"], PGSSLMODE="verify-full",
        PGSSLROOTCERT="/etc/ssl/certs/ca-certificates.crt",
    )
    lag = replica_probe(host, job["replica"])
    processes = []
    with Telemetry() as telemetry:
        started = time.time()
        try:
            for kind, command in commands:
                processes.append((kind, subprocess.Popen(
                    command, cwd=work, env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    **inherited_lock(),
                )))
            logs = {}
            for kind, process in processes:
                output, _ = process.communicate(timeout=240)
                logs[kind] = output
                if process.returncode:
                    raise RuntimeError(f"pgbench {kind} failed:\n{output}")
        finally:
            for _, process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=30)
    summaries = {}
    for kind, log in logs.items():
        tps = re.search(r"tps = ([\d.]+)", log)
        skipped = re.search(r"number of transactions skipped: (\d+)", log)
        failures = re.search(r"number of failed transactions: (\d+)", log)
        if not tps or not failures:
            raise RuntimeError(f"pgbench summary was incomplete:\n{log}")
        summaries[kind] = {
            "tps": float(tps[1]), "failed": int(failures[1]),
            "skipped": int(skipped[1]) if skipped else 0,
        }
        latencies = []
        for path in work.glob(f"{kind}.*"):
            for line in path.read_text().splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[2].isdigit():
                    latencies.append(int(fields[2]) / 1000)
        summaries[kind].update(
            sampled_latency_p95_ms=percentile(latencies, .95) if latencies else None,
            sampled_latency_p99_ms=percentile(latencies, .99) if latencies else None,
            sampled_latency_count=len(latencies),
        )
    return {
        "logs": logs, "summary": summaries, "replica_visibility_seconds": lag,
        "telemetry": telemetry.summary(started),
    }


def emit_artifact(path, job):
    encoded = path.read_text()
    result = json.loads(zlib.decompress(base64.b64decode(encoded, validate=True)))
    if result["job"] != job:
        raise RuntimeError("Existing artifact does not match the requested job")
    checksum = hashlib.sha256(encoded.encode()).hexdigest()
    print(f"BENCH_FILE:{path.name}:{len(encoded)}:{checksum}", flush=True)
    if len(encoded) <= 3500:
        print(f"BENCH_DATA:{encoded}", flush=True)
    return result


def main():
    global LOCK_FD
    job = json.loads(os.environ["JOB"])
    if sys.argv[1:] not in ([], ["--inspect"]):
        raise RuntimeError("Usage: worker.py [--inspect]")
    if not re.fullmatch("[a-f0-9]{16}", job["job_id"]) or job.get("format") != FORMAT:
        raise RuntimeError("Invalid worker job identity or checkpoint version")
    path = ROOT / f"{job['job_id']}.b64"
    started = ROOT / f"{job['job_id']}.started.json"
    with (ROOT / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('BENCH_STATUS:{"state":"busy"}', flush=True)
            raise SystemExit(75)
        LOCK_FD = lock.fileno()
        try:
            if started.exists() and json.loads(started.read_text()) != job:
                raise RuntimeError("Started job identity changed")
            if path.exists():
                result = emit_artifact(path, job)
            elif sys.argv[1:] == ["--inspect"]:
                state = "interrupted" if started.exists() else "absent"
                print("BENCH_STATUS:" + json.dumps({"state": state}), flush=True)
                return
            else:
                atomic_json(started, job)
                try:
                    operations = {
                        "build": build, "metadata": metadata, "measure": measure,
                        "supplement": supplement, "validate": validate_dataset,
                        "replica": lambda j: {
                            "visibility_seconds": replica_probe(j["host"], j["replica"], timeout=1800)
                        },
                    }
                    result = {"ok": True, "job": job, "result": operations[job["operation"]](job)}
                except Exception:
                    result = {
                        "ok": False, "job": job,
                        "error": traceback.format_exc().replace(os.environ["DB_PASSWORD"], "<redacted>"),
                    }
                encoded = base64.b64encode(
                    zlib.compress(json.dumps(result, default=str).encode(), level=9)
                ).decode()
                atomic_text(path, encoded)
                emit_artifact(path, job)
            if not result["ok"]:
                raise SystemExit(1)
        finally:
            LOCK_FD = None


if __name__ == "__main__":
    main()
