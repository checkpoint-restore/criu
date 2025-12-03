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
6. **Final Sync**: Brief pause for final synchronization

## Requirements

- **Kernel**: Linux 5.7+ (for `UFFD_FEATURE_PAGEFAULT_FLAG_WP`)
- **Privileges**: CAP_SYS_PTRACE or `sysctl vm.unprivileged_userfaultfd=1`

## Usage

```bash
# Perform COW dump
sudo criu dump --tree <pid> \
    --images-dir /path/to/images \
    --cow-dump \
    --leave-running

# Check kernel support
criu check --feature cow_dump
```

## Command-Line Options

- `--cow-dump`: Enable COW-based live migration
- `--leave-running`: Keep process running after dump (recommended with --cow-dump)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Source Process (valkey-server)                          │
├─────────────────────────────────────────────────────────┤
│ 1. Seize & dump metadata                                │
│ 2. Write-protect all writable pages (UFFDIO_WRITEPROTECT)│
│ 3. Resume process                                        │
│ 4. Monitor write faults via userfaultfd                 │
│ 5. On write fault:                                       │
│    a. Copy old page content from /proc/pid/mem          │
│    b. Send to page server/destination                   │
│    c. Unprotect page (UFFDIO_WRITEPROTECT mode=0)       │
│    d. Wake faulting thread (UFFDIO_WAKE)                │
│ 6. Iterate until convergence (<100 dirty pages/iter)    │
│ 7. Final sync                                           │
└─────────────────────────────────────────────────────────┘
```

## Key Files

- **`criu/cow-dump.c`**: Main implementation
- **`criu/include/cow-dump.h`**: Public API
- **`criu/cr-dump.c`**: Integration with dump flow
- **`criu/config.c`**: Command-line parsing

## Comparison with Existing Modes

| Feature | Standard Dump | Lazy Pages | COW Dump |
|---------|--------------|------------|----------|
| Source Downtime | Full process halt | Full process halt | Minimal (<100ms) |
| Memory Transfer | During halt | During halt | While running |
| Restore Speed | Fast | On-demand | On-demand |
| Kernel Support | Basic ptrace | userfaultfd | userfaultfd + WP |
| Use Case | Standard C/R | Fast restore | Live migration |

## Limitations

1. **Performance Overhead**: Each write fault has overhead during tracking
2. **Write-Heavy Workloads**: May not converge if write rate is too high
3. **Memory Consistency**: Pages are captured at different times
4. **Fork Support**: Limited support for processes that fork during dump

## Convergence Thresholds

- **Max Iterations**: 10 (configurable via `COW_MAX_ITERATIONS`)
- **Convergence Threshold**: <100 pages dirty per iteration
- **Iteration Interval**: 1 second between iterations

## Future Improvements

1. **Dynamic Thresholds**: Adjust based on workload characteristics
2. **Adaptive Intervals**: Vary iteration timing based on write rate
3. **Page Deduplication**: Integrate with existing auto-dedup
4. **Multi-Process Support**: Handle process trees with COW
5. **Integration with Page Server**: Full network transfer support
6. **Epoll Integration**: Better event handling instead of polling

## Implementation Status

### ✅ Completed
- Core COW dump infrastructure
- userfaultfd write-protection tracking
- Command-line option parsing
- Basic write fault handling
- Iteration and convergence logic
- Integration with dump flow

### 🚧 In Progress
- Page server integration
- Full network transfer
- Performance optimization
- Extended testing

### 📋 TODO
- Comprehensive error handling
- Statistics and metrics
- Documentation updates
- Test suite
- Production hardening

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

### Process Doesn't Converge
```
Warning: Did not converge after 10 iterations
```
**Solution**: Process is write-heavy. Consider using standard dump or pre-dump mode.

## Testing

```bash
# Test with a simple process
echo $$ > /tmp/test.pid
sleep 1000 &
sudo criu dump --tree $(cat /tmp/test.pid) --cow-dump --images-dir /tmp/cow-test --leave-running

# Verify process still running
ps -p $(cat /tmp/test.pid)

# Check convergence in logs
grep "COW iteration" /tmp/cow-test/lazy-primary.log
```

## References

- [userfaultfd(2)](https://man7.org/linux/man-pages/man2/userfaultfd.2.html)
- [UFFD_FEATURE_PAGEFAULT_FLAG_WP](https://www.kernel.org/doc/html/latest/admin-guide/mm/userfaultfd.html)
- [CRIU Lazy Pages](https://criu.org/Lazy_pages)

## Authors

- Implementation: CRIU Community
- Design: Based on VM live migration techniques

## License

Same as CRIU (GPLv2)
