# Benchmarking HorizonDB against Flexible Server

[日本語](README.md)

This benchmark creates a dedicated environment in Azure Japan East and compares the two services using HammerDB 6.1 TPROC-C. It does not use existing databases or VMs.

This repository contains only the code needed to reproduce the benchmark and offline tests. Measurement results, presentations, execution history, environment-specific identifiers, and credentials are not published. The `results/` directory generated during execution is also excluded from Git tracking.

## Prerequisites

Creating or resuming an actual Azure environment requires macOS Keychain, Python 3, Azure CLI, and `ssh-keygen`. No additional pip packages are required for the local Python environment. Tests also require `tclsh`; the tests alone can run on Linux.

```sh
git clone https://github.com/rioriost/horizon_bench.git
cd horizon_bench
az login
export AZURE_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az horizondb --help
python3 -m unittest -q
```

To use a different subscription, explicitly set `AZURE_SUBSCRIPTION_ID` to its UUID. If the variable is missing or incorrectly formatted, execution stops before creating a results directory or performing Azure operations. Use the original subscription when resuming or cleaning up a run.

If `az horizondb --help` is unavailable, obtain an Azure CLI installation and subscription that support HorizonDB. You need eligibility to use HorizonDB, service availability in Japan East, sufficient VM and database quotas, and permission to create resources and assign roles. Consult the current official documentation for CLI extensions and service availability. Offline tests do not use an Azure login or database credentials.

The client VMs run Ubuntu 24.04. `setup.sh` installs dependencies including Python 3, psycopg2, the PostgreSQL 17 client, pgbench, and HammerDB 6.1. The HammerDB distribution is verified using SHA-256. Initial setup requires outbound connectivity from the VMs to the Ubuntu, PostgreSQL, and GitHub distribution endpoints.

## Comparing the same data sizes and workloads

Both services use PostgreSQL 17, with one primary and one read replica, each with 8 vCPUs and 64 GiB of memory. HorizonDB's `--replica-count 2` includes the primary. Flexible Server uses `Standard_E8ds_v5` with 2 TiB of Premium SSD v2 storage, 12,000 IOPS, and 280 MB/s throughput. The 2 TiB disk provides room for indexes, WAL, and other overhead alongside the 1 TiB dataset. Storage internals and CPU generations differ, so this is a comparison of service configurations rather than identical hardware.

Two `Standard_F32as_v6` VMs generate the load. Normally, one is assigned to each service. Additional measurements near peak throughput connect both VMs to the same database. The benchmark records not only overall CPU utilization but also the busiest core, available memory, and network traffic. The two-client check is a single measurement and does not rigorously establish the limits of the clients.

The measured size of a 10-warehouse dataset is used to choose common warehouse counts that bring the combined table and index sizes to approximately 50 GiB, 250 GiB, and 1 TiB. The number of schema-build users never exceeds the warehouse count. A single-user trial on the calibration dataset must succeed before larger datasets are built. Execution stops if the measured size falls outside +/-10% of the target. The dedicated `tprocc` database is recreated only when moving to the next dataset size; a resumed run reuses completed datasets.

The standard mix of five TPROC-C transaction types is unchanged. The workload covers all warehouses, using 1, 8, 16, 32, 64, 128, and 256 users for the small and medium datasets, and 16, 64, and 256 users for the large dataset. Each condition is repeated three times with a two-minute warm-up and a five-minute measurement interval, alternating the execution order between services. HammerDB 6.1 automatically adds one monitoring VU, so `vuset vu` receives only the number of load-generating users. The startup delay is set to zero so that all users start during the warm-up, even at 256 users.

Each VU opens notification, SQLite, and PostgreSQL files. The 1,024-file limit inherited from the Azure execution environment is insufficient for 256 users, so the worker process raises its limit to at least 65,536 before launching HammerDB. A higher existing limit is left unchanged. If the maximum allowed by the OS is also below 65,536, execution fails without generating load. The applied limit is saved with the results.

Because `vurun` can return when its time limit is reached, the benchmark waits for all VUs to finish before retrieving and discarding the results. This additional wait is limited to ten minutes; failure to finish is recorded as a failed operation. Results are accepted only if the output contains the actual user count, successful completion notifications for every VU including the monitor, and response times for all five transaction types. Results reporting VU failures or missing measurement data are also rejected. Saved data includes NOPM, TPM, per-transaction response times, database statistics, data growth, and client utilization. Response times use HammerDB's standard aggregation, which includes the warm-up; client utilization is restricted to the five-minute measurement interval. This is not an officially audited TPC-C benchmark, so results are not labeled tpmC.

Even with two clients, NOPM comes from database-wide counters. The two clients' values are not added together; the first client's monitoring result is used. Because data grows between repetitions, sizes before and after updates are recorded. These are warm-cache measurements and do not guarantee a cold cache.

At 250 GiB, a supplemental test uses pgbench to run reads and updates concurrently against the same customer table. The total offered load is 1,000 transactions per second, with read-to-write ratios of 80:20 and 50:50. Total connection counts are 20, 80, and 160, and reads are routed to either the primary or the replica. Recorded metrics include achieved TPS, failures and skipped transactions, separate read/write p95 and p99 latencies from a 1% sample, and the time until an update becomes visible on the replica. The specified ratios describe offered rates; failures or skipped transactions can make the actual completion ratios differ.

## Preserving and resuming interrupted environments

Errors, deadline expiration, Ctrl+C, and SIGTERM do not delete databases, disks, or execution records. When the local controller detects an interruption, it verifies ownership and deallocates the client VMs. If stopping them fails, the error is recorded and the environment is preserved. The dedicated resource group is deleted, and its absence verified, only after a successful run with saved results or when `--cleanup` is explicitly requested.

If an Azure REST GET that reads Run Command status fails due to DNS resolution, it is retried up to six times including the initial attempt, with delays of 2, 4, 8, 16, and 30 seconds. Both waits and calls remain subject to the original execution deadline and a one-hour limit per operation. Non-DNS failures and create, update, start, stop, and delete operations are not automatically retried. VMs stopped externally are not automatically restarted.

Execution requires macOS, Python 3, an authenticated Azure CLI session, and permission to create resources and assign roles in the selected subscription. The database password is stored in macOS Keychain and verified to be readable before deployment. It is passed directly to the OS API, not as a Keychain command-line argument. Resuming requires both the Keychain item on the same Mac and `results/<run_id>/`. Local regression checks also use `tclsh`.

```sh
python3 -m unittest -q
# Start a new run. Its run_id is also recorded in results/<run_id>/state.json.
python3 infra.py run_benchmark.py

# Reconnect to an active environment. Stopped VMs are not started automatically.
python3 infra.py --resume RUN_ID

# After checking why the VMs were stopped externally, explicitly allow startup.
python3 infra.py --resume RUN_ID --start-clients

# If the execution deadline has passed, review costs and extend the stop deadline by 16 hours.
python3 infra.py --resume RUN_ID --start-clients --extend-hours 16

# Keep saved results, but delete the dedicated Azure environment and Keychain item.
python3 infra.py --cleanup RUN_ID
```

On resume, the controller checks the subscription, resource group name, ownership tags, and resource configuration before reusing existing resources. If local execution stopped just after Azure accepted a creation request, it checks whether the resource exists and its provisioning state before proceeding. If a resource or group previously recorded as fully created is missing, execution stops rather than silently recreating it. Resuming and cleaning up the same run concurrently is also prohibited.

Before submitting each build or measurement operation, the controller saves its stable key, VM, inputs, job ID, and collection state in `progress.json`. A resumed run reconnects to an active Run Command or uses saved results if it has finished. Results can also be recovered from files on the VM even if the original command no longer exists. The VM reuses results for the same job. If the parent process exits while HammerDB or pgbench remains active, a lock inherited by child processes prevents duplicate execution.

When a build completes, the run ID, dataset ID, warehouse count, and build results are also recorded in the database. Before applying load, the controller checks these against the current database rather than trusting local checkpoints alone. Completed calibration and smaller dataset stages are not rebuilt when resuming a larger stage. However, HammerDB schema creation itself cannot resume partway through, so **only an incomplete build requires recreating that service's database for the affected stage**. The other service's completed database and the infrastructure are preserved.

Completed measurements are not repeated, and CSV files are regenerated from saved results without duplicates. Two-client measurements are accepted only when both results from the original pair are available. If either is incomplete, the controller verifies that the old jobs have stopped and reruns both clients with a new start time. Updates made during interrupted or rejected attempts are not rolled back. If the checkpoint format, load-generation code, or input conditions have changed, execution stops rather than mixing results from different conditions.

A new run allocates 15 hours to execution and the remaining hour to stopping and post-processing. A stop timer is also installed on the first VM for 16 hours after startup; it does not delete databases or disks. It stops the second VM before stopping the first. The timer's managed identity receives only permission to read the resource group and operate the individual VMs, not permission to delete the group. Resuming does not automatically extend the deadline; an extension requires `--extend-hours`.

The timer on a VM does not run while that VM is deallocated. The benchmark does not change organizational policies or automatically restart VMs in response to external stops. The resume feature cannot restore a deleted environment.

## Database and storage charges continue while an environment is preserved

Deallocating client VMs does not eliminate charges for databases, disks, public IP addresses, and other resources. Because interruptions no longer trigger full deletion, there is no automatic deletion deadline for the entire environment. Delete runs that are no longer needed with `--cleanup RUN_ID`.

Before running, review database, VM, and storage prices and costs in the target region. Build time and storage retained during interruptions also incur charges, so completion within a budget is not guaranteed. Azure budget alerts do not stop billing. If measured build speed indicates that the remaining work cannot finish before the deadline, the affected stage is paused and the reason recorded. Work that was not performed is never treated as measured.

## Handling results and connection information

`results/<run_id>/` stores state, resume records, Azure configuration, per-measurement JSON files, and TPROC-C CSV files. State and result files are replaced only after writing and syncing a temporary file. Passwords are not written to these files; they are passed to VMs as protected Run Command parameters. The Keychain item is deleted only after environment deletion is confirmed. No inbound SSH rule is opened for the VMs. SQL connections verify certificates and hostnames.

Measurement logs are saved in full. Only highly repetitive data-build progress lines are reduced to the first 50 and last 50 lines, with the omitted line count and original log hash recorded. CPU and similar metrics are saved as aggregates calculated from samples taken during measurement. Full progress logs for completed builds remain on the VMs but disappear when the dedicated environment is deleted.

Azure management metrics are saved at the finest interval commonly supported by the API for each requested metric batch. Not every metric supports one-minute intervals. Check the interval included in the response and distinguish these metrics from the per-measurement sample aggregates of client utilization.

Results are compressed, retrieved through the Azure management API, and verified by hash. They normally fit in one response; only large results are split into chunks. Run Commands are deleted after their terminal state is recorded, and deletion must finish before the next operation begins. Results on the VM remain available if collection is interrupted. Commands that are still running are not deleted during interruption cleanup. Resuming also removes abandoned terminal commands to avoid reaching the limit of 25 commands per VM. Before creating databases, the controller tests retrieval of an approximately 3.6 KB result and command deletion on both VMs. It neither changes organizational policies that disable public Blob Storage access nor creates storage for transfers.

## References

- [HorizonDB compute replicas](https://learn.microsoft.com/azure/horizondb/configure-maintain/concepts-compute-replicas)
- [Connecting to HorizonDB](https://learn.microsoft.com/azure/horizondb/connectivity/how-to-connect-query-guide)
- [HammerDB 6.1](https://github.com/TPC-Council/HammerDB/releases/tag/v6.1)
- [HammerDB TPROC-C](https://www.hammerdb.com/docs/ch03s05.html)
- [Managed Run Command for Linux VMs](https://learn.microsoft.com/azure/virtual-machines/linux/run-command-managed)

## License

[MIT License](LICENSE)
