# COW Dump - Copy-on-Write Live Migration for CRIU

## Overview

COW (Copy-on-Write) dump is a new feature that enables live migration of processes with minimal downtime by using userfaultfd write-protection to track memory modifications while the process continues running.

## How It Works

Traditional CRIU lazy-pages mode keeps the source process halted during memory transfer.
COW dump changes that by keeping write tracking active while restore proceeds.

1. **Per-task COW registration while frozen**
   - CRIU registers lazy-capable writable VMAs in parasite context with userfaultfd WP.
   - VMAs that fail registration are explicitly marked as fallback and dumped by the normal path.
2. **Base dump with tracked-vs-fallback split**
   - Only successfully registered VMAs use COW/lazy transfer.
   - Non-registerable VMAs are transferred deterministically in the non-COW path.
3. **Session monitor starts once**
   - A single monitor thread starts after all dump tasks are prepared (process-tree aware).
   - It watches all task UFFDs for WP faults.
4. **Write-fault handling**
   - On first write fault, CRIU snapshots page content, queues it for transfer, unprotects, and wakes the task.
5. **Bulk stream close contract**
   - Sender ends stream with `nr_pages == 0` close marker.
   - Receiver sends a 32-bit status ACK.
   - Sender treats ACK success as completion; for old peers that close without ACK, sender accepts clean EOF/close as compatibility fallback.

## Process Tree Notes

- COW tracking state is session-level, but registration is per task.
- Lazy VMA lookup is keyed by `dst_id` and address to avoid cross-process mismatches.
- Page counts and transfers are scoped per destination image (`dst_id`).

## Latency Measurement

For cutover tuning, track:
- source pause p50/p95/p99 around dump-resume boundary,
- restore completion time,
- end-to-end migration time.

Use workload traffic during migration (not idle benchmarks), and compare baseline lazy mode vs `--cow-dump`.

## Real Client Scenario Harness

Use the traffic harness to simulate a real app while migration is running:
- continuous writes/reads to source,
- continuous reads to replica,
- intentional misrouted writes to replica (must be rejected with `READONLY`),
- client-side latency, error, and outage-window tracking,
- post-run replication catch-up and sampled value integrity checks.

Run:
```bash
./scripts/run_migration_scenario.sh 40
```

Artifacts:
- Harness report JSON: `/tmp/valkey_traffic_harness_report.json`
- Harness live log: `/tmp/valkey_traffic_harness.log`

Key pass conditions:
- `replica_write_accepted == 0`
- `replication_caught_up == true`
- `sample_value_mismatches == 0`
- `source_expected_mismatches == 0`
- `replica_expected_mismatches == 0`

## Requirements

- **Kernel**: Linux 5.7+ (for `UFFD_FEATURE_PAGEFAULT_FLAG_WP`)
- **Privileges**: CAP_SYS_PTRACE or `sudo sysctl vm.unprivileged_userfaultfd=1`

## update to allow replication
```bash
sudo chown -R ubuntu:ubuntu /var/lib/valkey
sudo chmod 750 /var/lib/valkey
```

## Usage
At the source create a custom valkey.conf at /etc/valkey/valkey.conf 
```bash
# Perform COW dump src
sudo cp valkey.confg /etc/valkey/valkey.conf 
```

At the source call to
```bash
# Perform COW dump src
sudo scripts/./dump_replica_lazy.sh

```

At the dest 
```bash
# Perform COW dump src
sudo scripts/./orchestrate_kill_and_sync.sh

```

## Command-Line Options

- `--cow-dump`: Enable COW-based live migration
- `--leave-running`: Keep process running after dump (recommended with --cow-dump)


## Troubleshooting

### Kernel Doesn't Support Write-Protect
```
Error: userfaultfd write-protect not supported (need kernel 5.7+)
```
**Solution**: Upgrade to Linux 5.7 or newer

### Permission Denied
```
Error: userfaultfd requires CAP_SYS_PTRACE or sysctl vm.unprivileged_userfaultfd=1
```
**Solution**: Run as root or configure sysctl
