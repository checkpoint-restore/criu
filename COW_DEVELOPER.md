# COW Dump Developer Setup Guide

Complete setup guide for CRIU COW (Copy-on-Write) dump development and testing
with Valkey live migration.

## Prerequisites

- **Two machines** (PRIMARY and REPLICA) with network connectivity
- **Ubuntu 22.04+ or 24.04** (tested on 24.04 LTS)
- **Linux kernel 5.7+** (for userfaultfd write-protect support)
- **Shared storage** accessible from both machines (e.g., AWS FSx, NFS)
- **SSH access** between machines

---

## 1. Kernel Requirements

### Check Kernel Version

```bash
uname -r
# Must be >= 5.7 for userfaultfd write-protect (UFFD_FEATURE_PAGEFAULT_FLAG_WP)
# Note: UFFD_FEATURE_WP_ASYNC is Linux 6.7+ and not enabled by default.
```

### Enable Unprivileged Userfaultfd

```bash
# Check current setting
cat /proc/sys/vm/unprivileged_userfaultfd

# Enable (temporary)
sudo sysctl -w vm.unprivileged_userfaultfd=1

# Enable (persistent)
echo "vm.unprivileged_userfaultfd=1" | sudo tee /etc/sysctl.d/99-userfaultfd.conf
sudo sysctl -p /etc/sysctl.d/99-userfaultfd.conf
```

### Verify Userfaultfd Support

```bash
# Check kernel config (if available)
grep USERFAULTFD /boot/config-$(uname -r)
# Should show: CONFIG_USERFAULTFD=y
```

---

## 2. Install Build Dependencies

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    git \
    libprotobuf-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    protobuf-compiler \
    python3-protobuf \
    libbsd-dev \
    libcap-dev \
    libnet1-dev \
    libnl-3-dev \
    libnftables-dev \
    libgnutls28-dev \
    libaio-dev \
    uuid-dev \
    asciidoc \
    xmlto
```

### Python Tools (for CRIT and tests)

```bash
sudo apt install -y python3-pip python3-venv
pip3 install protobuf ipaddr pyaml
```

---

## 3. Build CRIU

### Clone and Build

```bash
# Clone repository
git clone https://github.com/checkpoint-restore/criu.git
cd criu

# Switch to COW branch (if not on main)
git checkout criu-cow

# Build
make -j$(nproc)

# Verify build
./criu/criu --version
./criu/criu check
```

### Install System-Wide (Optional)

```bash
sudo make install
# Installs to /usr/local/sbin/criu by default
```

### Verify COW Support

```bash
# Check that CRIU source has COW support
grep "cow_dump" ./criu/config.c
# Should show multiple lines with cow_dump

# Note: --cow-dump is not listed in --help but works
# The option was added for live migration and is functional
```

---

## 4. Install Valkey

### From Ubuntu Repository (Ubuntu 24.04+)

```bash
# Valkey is available in Ubuntu's universe repository
sudo apt update
sudo apt install -y valkey-server valkey-tools
```

### From Source (Alternative, Recommended for Latest)

```bash
git clone https://github.com/valkey-io/valkey.git
cd valkey
make -j$(nproc)
sudo make install
```

### Verify Installation

```bash
valkey-server --version
valkey-cli --version
```

### Service Management (Important)

We rely on **systemd** on the **PRIMARY** to auto-restart Valkey after the
script kills it at the start of each run. On the **REPLICA**, Valkey must be
**stopped** before restore; CRIU restore brings it back.

**PRIMARY (master):**
- Keep `valkey-server` **enabled and running** (systemd restart is required).
- Do **not** manually stop it before a run; `scripts/migrate.sh` will `pkill`
  it and systemd will restart it automatically.

**REPLICA (destination):**
- Ensure Valkey is **not running** before each run.
- `scripts/restore.sh` starts by killing Valkey.

### COW Run Order (Current Implementation)

Use this order as the source of truth for debugging:

1. Dump phase registers per-task COW VMAs (parasite UFFD WP).
2. Non-registerable VMAs are marked fallback and dumped via normal path.
3. Base dump completes while source is still frozen.
4. Just before source resume, CRIU starts one session monitor thread.
5. Source resumes; monitor handles write faults and queues COW pages.
6. Bulk sender ends each image stream with `nr_pages == 0` close marker.
7. Receiver sends 32-bit ACK on end marker; sender accepts ACK or clean EOF for compatibility.

If this contract is broken, fix CRIU core first; do not rely on script timeouts.

### Performance Measurement Method

For each run, capture:

- cutover pause p50/p95/p99 (source freeze/resume boundary),
- restore completion time,
- full migration wall time.

Measure under active traffic (not idle), and compare baseline lazy mode vs `--cow-dump`.

---

## 5. Setup Shared Storage

COW dump requires shared storage accessible from both PRIMARY and REPLICA for
CRIU image files and coordination signals.

### Option A: AWS FSx for Lustre

```bash
# Mount FSx (example)
sudo mkdir -p /fsx
sudo mount -t lustre fs-xxxxx.fsx.us-east-1.amazonaws.com@tcp:/xxxxx /fsx

# Create lazy directory
sudo mkdir -p /fsx/lazy
sudo chmod 777 /fsx/lazy

# Add to fstab for persistence
echo "fs-xxxxx.fsx.us-east-1.amazonaws.com@tcp:/xxxxx /fsx lustre defaults,_netdev 0 0" | sudo tee -a /etc/fstab
```

### Option B: NFS

```bash
# On NFS server
sudo apt install -y nfs-kernel-server
sudo mkdir -p /srv/criu-images
sudo chown nobody:nogroup /srv/criu-images
echo "/srv/criu-images *(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
sudo exportfs -a

# On both PRIMARY and REPLICA
sudo apt install -y nfs-common
sudo mkdir -p /fsx/lazy
sudo mount -t nfs nfs-server:/srv/criu-images /fsx/lazy
```

### Verify Shared Storage

```bash
# On PRIMARY
echo "test" > /fsx/lazy/test.txt

# On REPLICA
cat /fsx/lazy/test.txt
# Should show: test

# Cleanup
rm /fsx/lazy/test.txt
```

---

## 6. Setup SSH Between Machines

### Generate SSH Key (on PRIMARY)

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/replica.pem -N ""
```

### Copy Public Key to REPLICA

```bash
ssh-copy-id -i ~/.ssh/replica.pem.pub ubuntu@<REPLICA_HOST>
```

### Test Connection

```bash
ssh -i ~/.ssh/replica.pem ubuntu@<REPLICA_HOST> "hostname"
```

---

## 7. Configure Environment

### Create .env File

Create `scripts/.env` on both machines (or on shared storage):

```bash
cat > scripts/.env << 'EOF'
# CRIU Migration Configuration
# Source this file in migration scripts

# Primary (Source) Machine
PRIMARY_HOST="<PRIMARY_PUBLIC_HOSTNAME>"
PRIMARY_IP="<PRIMARY_PRIVATE_IP>"

# Replica (Destination) Machine
REPLICA_HOST="<REPLICA_PUBLIC_HOSTNAME>"
REPLICA_IP="<REPLICA_PRIVATE_IP>"

# CRIU lazy-pages port
CRIU_PORT=9002

# Shared storage for CRIU images
IMAGES_DIR="/fsx/lazy"

# SSH key for cross-machine access
SSH_KEY="/home/ubuntu/.ssh/replica.pem"

# Valkey
VALKEY_PORT=6379

# Timeouts
WAIT_TIMEOUT=300  # 5 minutes

# Data fill (for testing)
DEFAULT_DATA_SIZE_GB=40
EOF
```

### Get IP Addresses

```bash
# Private IP (for internal communication)
hostname -I | awk '{print $1}'

# Public hostname (for SSH)
curl -s http://169.254.169.254/latest/meta-data/public-hostname
```

---

## 8. Network Configuration

### Open Required Ports

```bash
# On PRIMARY - allow CRIU page server
sudo ufw allow 9002/tcp

# On REPLICA - allow Valkey replication
sudo ufw allow 6379/tcp

# Or using iptables
sudo iptables -A INPUT -p tcp --dport 9002 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6379 -j ACCEPT
```

### AWS Security Groups

If using AWS, ensure security groups allow:
- **PRIMARY → REPLICA**: TCP 22 (SSH)
- **REPLICA → PRIMARY**: TCP 9002 (CRIU page server)
- **PRIMARY ↔ REPLICA**: TCP 6379 (Valkey replication)

---

## 9. Verify Setup

### Run on Both Machines

```bash
# 1. Check CRIU
./criu/criu check
./criu/criu check --feature uffd-noncoop

# 2. Check kernel
uname -r  # >= 5.7

# 3. Check userfaultfd
cat /proc/sys/vm/unprivileged_userfaultfd  # Should be 1

# 4. Check Valkey
valkey-server --version

# 5. Check shared storage
ls -la /fsx/lazy/

# 6. Check network connectivity
nc -zv <OTHER_MACHINE_IP> 9002
```

---

## 10. Test Migration

### Quick Test (1GB)

```bash
# On PRIMARY
cd /path/to/criu
./scripts/migrate.sh 1
```

### Expected Output

```
[HH:MM:SS] Step 1: Kill processes...
[HH:MM:SS] Step 2: Check valkey...
  PID: 12345
[HH:MM:SS] Step 3: Fill ~1GB using valkey-benchmark...
  Memory: 1.05G
[HH:MM:SS] Step 4: Clean /fsx/lazy...
[HH:MM:SS] Step 5: Start replica (will wait for page server)...
[HH:MM:SS] Step 5b: Wait for replica ready signal...
  Replica ready
[HH:MM:SS] Step 6: CRIU dump...
[HH:MM:SS] Step 7: Wait for replica...
[HH:MM:SS] Step 7b: Stop dump process...
[HH:MM:SS] Step 8: Check replica...
================================================================
Migration complete!
  Source Memory:   1.05G
  Replica Memory:  1.05G
----------------------------------------------------------------
  CRIU Timing (dump):
    dump_one_task TOTAL:   0.XXXs
================================================================
```

---

## 11. Run Order / State Checklist

Use this checklist **every time** to avoid hangs:

**Before the run (PRIMARY + REPLICA):**
- Same git branch/commit on both machines.
- `scripts/.env` **identical** on both machines (copy it to replica).
- **PRIMARY Valkey**: `systemctl enable --now valkey-server` (must be running).
- **REPLICA Valkey**: **not running** before the run.
- Shared storage mounted on both (`/fsx/lazy`).
- Ports open: `9002` (CRIU page server), `6379` (Valkey replication).

**Run (PRIMARY):**
- `sudo ./scripts/migrate.sh <GB>`
- Script flow:
  - Step 1 kills Valkey + CRIU on both.
  - Step 2 waits for Valkey on PRIMARY to restart (systemd handles it).
  - Step 5 starts `restore.sh` on REPLICA (kills replica Valkey and waits for page server).
  - Replica runs `criu lazy-pages` + `criu restore` **with `--cow-dump`**.

**After the run:**
- Replica Valkey should respond (`valkey-cli ping`).
- If it hangs:
  - Check `/fsx/lazy/lazy-restore.log` and `/fsx/lazy/lazy-server.log`.
  - **Symptom of missing `--cow-dump`:** `lazy-restore.log` empty and `lazy-server.log`
    ends with `page_server_start_read`. Fix by ensuring `--cow-dump` is present in
    `scripts/restore.sh` for both `lazy-pages` and `restore`.

---

## 12. Troubleshooting

### CRIU Check Fails

```bash
# Run detailed check
sudo ./criu/criu check -v4

# Common issues:
# - "Dirty tracking" → Need CONFIG_MEM_SOFT_DIRTY=y
# - "Userfaultfd" → Enable vm.unprivileged_userfaultfd
```

### Page Server Connection Refused

```bash
# Check if port is open
sudo netstat -tlnp | grep 9002

# Check firewall
sudo ufw status
sudo iptables -L -n
```

### Shared Storage Not Accessible

```bash
# Check mount
mount | grep fsx
df -h /fsx/lazy

# Remount if needed
sudo mount -a
```

### Valkey Not Responding After Restore

```bash
# Check logs
cat /fsx/lazy/lazy-restore.log

# Common issues:
# - TCP sockets not closed → Use --tcp-close flag
# - File permissions → Use --skip-file-rwx-check flag
```

### COW Dump Not Working

```bash
# Check kernel support
./criu/criu check --feature uffd-noncoop

# Optional: check kernel logs for userfaultfd hints
dmesg | grep -i userfaultfd
```

---

## 12. Development Workflow

### Build After Changes

```bash
make -j$(nproc)
```

### Run ZDTM Tests

```bash
# Single test
sudo ./test/zdtm.py run -t zdtm/static/env00

# COW-related tests
sudo ./test/zdtm.py run -t zdtm/static/cow00
sudo ./test/zdtm.py run -t zdtm/static/cow01
```

### Debug Logging

```bash
# Verbose dump
sudo ./criu/criu dump -t $PID -D /tmp/images -v4 --cow-dump --lazy-pages

# Check logs
cat /tmp/images/*.log
```

---

## 13. File Reference

| File | Purpose |
|------|---------|
| `scripts/migrate.sh` | Master migration script (run on PRIMARY) |
| `scripts/restore.sh` | Restore script (run on REPLICA) |
| `scripts/wait_and_replicate.sh` | Configure Valkey replication |
| `scripts/.env` | Environment configuration |
| `criu/cow-dump.c` | COW dump implementation |
| `criu/include/cow-dump.h` | COW dump API |
| `criu/page-xfer.c` | Page transfer with COW integration |

---

## 14. Quick Reference Commands

**Note:** Some COW-related flags (`--cow-dump`, `--ext-unix-sk`) are not shown in
`--help` but are functional. They were added for the COW dump feature.

```bash
# Start Valkey (foreground, no persistence)
valkey-server --protected-mode no --save ""

# Fill Valkey with test data
valkey-benchmark -t set -d 64000 -r 25300 -n 30000 -q

# Check Valkey memory
valkey-cli info memory | grep used_memory_human

# Manual CRIU dump with COW
sudo ./criu/criu dump \
    --tree $PID \
    --images-dir /fsx/lazy \
    --cow-dump \
    --lazy-pages \
    --address $PRIMARY_IP \
    --port 9002 \
    --tcp-close \
    --ext-unix-sk \
    --leave-running \
    -v4

# Manual CRIU restore with lazy-pages
sudo ./criu/criu lazy-pages \
    --images-dir /fsx/lazy \
    --page-server \
    --address $PRIMARY_IP \
    --port 9002 \
    --cow-dump \
    -v4 &

sudo ./criu/criu restore \
    --images-dir /fsx/lazy \
    --lazy-pages \
    --tcp-close \
    --cow-dump \
    --skip-file-rwx-check \
    -v4
```
