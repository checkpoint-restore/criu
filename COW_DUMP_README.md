# COW Dump - Copy-on-Write Live Migration for CRIU

## Overview

COW (Copy-on-Write) dump is a new feature that enables live migration of processes with minimal downtime by using userfaultfd write-protection to track memory modifications while the process continues running.

## How It Works

Traditional CRIU lazy-pages mode keeps the source process halted during memory transfer. COW dump improves on this by:

1. **Initial Snapshot**: Takes a quick snapshot of process state (file descriptors, credentials, etc.)
2. **Write Protection**: Uses userfaultfd with `UFFD_FEATURE_PAGEFAULT_FLAG_WP` to write-protect all writable memory pages
3. **Resume Process**: The source process continues running immediately
4. **Track Writes**: On each write fault, COW dump:
   - Copies the old page content before it's modified
   - Sends it to the destination
   - Unprotects the page
   - Allows the write to proceed
5. **Iterative Convergence**: Continues until the write rate decreases below a threshold

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


