"""Pause only run-owned clients; never erase unfinished databases or disks."""

import argparse
import datetime as dt
import json
import time
import urllib.error
import urllib.request


def request(url, *, headers=None, method="GET"):
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers or {}, method=method), timeout=60
    ) as response:
        data = response.read()
        return json.loads(data) if data else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("subscription")
    parser.add_argument("group")
    parser.add_argument("run_id")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.group != f"rg-horizon-bench-{args.run_id}":
        raise ValueError("Refusing to pause an unexpected resource group")
    url = (
        f"https://management.azure.com/subscriptions/{args.subscription}"
        f"/resourcegroups/{args.group}?api-version=2021-04-01"
    )
    for attempt in range(30):
        try:
            token = request(
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F",
                headers={"Metadata": "true"},
            )["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            group = request(url, headers=headers)
            if (group.get("tags") or {}).get("BenchmarkRun") != args.run_id:
                raise RuntimeError("Run ownership tag does not match")
            expires = dt.datetime.fromisoformat(group["tags"]["ExpiresUTC"])
            if not args.check and dt.datetime.now(dt.timezone.utc) < expires:
                print("Pause deadline was extended; ignoring the old timer", flush=True)
                return
            if args.check:
                for name in ("bench-client-2", "bench-client-1"):
                    vm_url = url.split("?")[0] + (
                        f"/providers/Microsoft.Compute/virtualMachines/{name}?api-version=2024-11-01"
                    )
                    vm = request(vm_url, headers=headers)
                    if (vm.get("tags") or {}).get("BenchmarkRun") != args.run_id:
                        raise RuntimeError("Client ownership tag does not match")
                print("WATCHDOG_ACCESS_OK")
            else:
                for name in ("bench-client-2", "bench-client-1"):
                    base = url.split("?")[0] + f"/providers/Microsoft.Compute/virtualMachines/{name}"
                    vm = request(base + "?api-version=2024-11-01", headers=headers)
                    if (vm.get("tags") or {}).get("BenchmarkRun") != args.run_id:
                        raise RuntimeError("Client ownership tag does not match")
                    request(base + "/deallocate?api-version=2024-11-01", headers=headers, method="POST")
                    print(f"Client pause requested: {name}; databases and disks retained", flush=True)
                    if name == "bench-client-2":
                        for _ in range(180):
                            view = request(base + "/instanceView?api-version=2024-11-01", headers=headers)
                            if any(s["code"] == "PowerState/deallocated" for s in view["statuses"]):
                                break
                            time.sleep(10)
                        else:
                            raise TimeoutError("Second client did not deallocate")
            return
        except urllib.error.HTTPError as error:
            if error.code not in (403, 429, 500, 502, 503, 504) or attempt == 29:
                raise
            print(f"Watchdog HTTP {error.code}; retry {attempt + 1}", flush=True)
            time.sleep(20)


if __name__ == "__main__":
    main()
