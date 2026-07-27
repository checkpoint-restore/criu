#!/bin/bash

# This script runs inside Lima VMs to set up and run CI tests.
# It is invoked with a command name, e.g.:
#   lima.sh centos-stream-setup
#   lima.sh centos-stream-test
#   lima.sh fedora-stable-setup
#   lima.sh fedora-stable-test
#   lima.sh fedora-next-setup
#   lima.sh fedora-next-test
#   lima.sh fedora-no-vdso-setup
#   lima.sh fedora-no-vdso-test
#   lima.sh fedora-non-root-setup
#   lima.sh fedora-non-root-test

set -e
set -x

CRIU_DIR="${CRIU_DIR:-/home/criu}"

centos-stream-setup() {
	# Enable CRB repository
	dnf config-manager --set-enabled crb
	# Install EPEL
	dnf -y install epel-release
	# CentOS Stream 10+ defaults to nftables
	if [ "$(rpm -E '%{rhel}')" -ge 10 ] 2>/dev/null; then
		dnf -y install nftables-devel
	fi
	# Install build/test dependencies
	"${CRIU_DIR}"/contrib/dependencies/dnf-packages.sh
	# Disable sssd to avoid zdtm test failures in pty04
	systemctl stop sssd || true
	# Set SELinux to permissive mode; selinux tests still run but
	# are not blocked by the restricted service context of CI.
	setenforce 0
	# The rpc test cases are running as user #1000
	adduser -u 1000 test
}

centos-stream-test() {
	# Increase the max thread limit for the thread-bomb test
	sysctl -w kernel.threads-max=100000

	# Newer systemd versions limit the number of tasks per user via
	# cgroup pids controller. Remove the limit for the root user.
	systemctl set-property user-0.slice TasksMax=infinity

	local compile_flags=""
	# CentOS Stream 10+ defaults to nftables
	if [ "$(rpm -E '%{rhel}')" -ge 10 ] 2>/dev/null; then
		compile_flags="NETWORK_LOCK_DEFAULT=NETWORK_LOCK_NFTABLES"
	fi

	cd "${CRIU_DIR}"
	make -C scripts/ci local \
		SKIP_CI_PREP=1 CC=gcc CD_TO_TOP=1 \
		ZDTM_OPTS="-x zdtm/static/socket-raw" \
		COMPILE_FLAGS="${compile_flags}"
}

_common_setup() {
	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
	systemctl mask sssd

	# The shellcheck tool misunderstands the "do" to be from a loop
	# shellcheck disable=SC1010
	dnf -y do --action=upgrade \* --action=install make podman
}

_common_test() {
	# Increase the max thread limit for the thread-bomb test
	sysctl -w kernel.threads-max=100000

	# Allow memory overcommit. The thread-bomb test creates 1024
	# threads that each create a successor after restore. In a
	# memory-constrained VM the heuristic overcommit check can
	# deny mmap for new thread stacks, and glibc maps ENOMEM to
	# EAGAIN in pthread_create.
	sysctl -w vm.overcommit_memory=1

	# Newer systemd versions limit the number of tasks per scope/slice
	# via cgroup pids controller. Set the system-wide default to
	# unlimited and also remove the limit for the root user's slice.
	# Without this, podman container scopes inherit the default
	# TasksMax and thread-bomb fails with EAGAIN.
	mkdir -p /etc/systemd/system.conf.d
	printf '[Manager]\nDefaultTasksMax=infinity\n' \
		> /etc/systemd/system.conf.d/50-tasks.conf
	systemctl daemon-reload
	systemctl set-property user-0.slice TasksMax=infinity

	# Some tests in the container need selinux to be disabled.
	# In the container it is not possible to change the state of selinux.
	# Let's just disable it for this test run completely.
	setenforce Permissive

	cd "${CRIU_DIR}"
	# excluding zdtm/static/socket-tcpbuf-local in this setup as it fails
	# sometimes: https://github.com/checkpoint-restore/criu/issues/2987
	make -C scripts/ci fedora-rawhide \
		CONTAINER_RUNTIME=podman \
		BUILD_OPTIONS="--security-opt seccomp=unconfined" \
		ZDTM_OPTS="-x zdtm/static/socket-tcpbuf-local"
}

fedora-stable-setup() {
	# Upgrade the kernel to the latest vanilla stable one
	dnf -y copr enable @kernel-vanilla/stable
	_common_setup
}

fedora-stable-test() {
	_common_test
}

fedora-next-setup() {
	# Upgrade the kernel to the latest vanilla next one
	dnf -y copr enable @kernel-vanilla/next
	_common_setup
}

fedora-next-test() {
	_common_test
}

fedora-no-vdso-setup() {
	"${CRIU_DIR}"/contrib/dependencies/dnf-packages.sh
	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
	systemctl mask sssd
	# Disable VDSO; the VM is rebooted between setup and test
	grubby --update-kernel ALL --args="vdso=0"
}

fedora-no-vdso-test() {
	cd "${CRIU_DIR}"
	make -j"$(nproc)"
	./test/zdtm.py run -a --keep-going
	# This test requires pidfd_getfd which is guaranteed in Fedora 33.
	# It is skipped from -a because it runs in RPC mode only.
	./test/zdtm.py run -t zdtm/transition/pidfd_store_sk --rpc --pre 2
}

fedora-non-root-setup() {
	"${CRIU_DIR}"/contrib/dependencies/dnf-packages.sh
	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
	systemctl mask sssd
	# The rpc test cases are running as user #1000
	adduser -u 1000 test
	# The user-namespace test (unshare --map-auto) needs subordinate
	# UID/GID ranges so that GID 65534 (nobody) is mapped inside the
	# namespace.  Without this, zdtm.py --rootless fails with EINVAL
	# on setgid(65534).
	echo "root:100000:65536" >> /etc/subuid
	echo "root:100000:65536" >> /etc/subgid
}

fedora-non-root-test() {
	cd "${CRIU_DIR}"
	make -j"$(nproc)"

	# Make the source tree writable by non-root users.  On GitHub
	# Actions limactl copy preserves the runner's permissions (755
	# directories), so test binaries running as non-root cannot
	# create output files without this.
	chmod -R a+rwX .

	# Setting the capability should be the only line needed to run
	# as non-root on Fedora.  In other environments either set
	# /proc/sys/kernel/yama/ptrace_scope to 0 or grant
	# cap_sys_ptrace to criu.
	setcap cap_checkpoint_restore+eip criu/criu

	# Run it once as non-root.
	# Remove any root-owned dump directories from make so the
	# non-root user can create its own.
	criu/criu check --unprivileged
	rm -rf test/dump
	./test/zdtm.py run \
		-t zdtm/static/env00 \
		-t zdtm/static/pthread00 \
		-f h --rootless

	# Run it as root with '--rootless'
	sudo ./test/zdtm.py run \
		-t zdtm/static/env00 \
		-t zdtm/static/pthread00 \
		-f h
	sudo chmod 777 test/dump/zdtm/static/{env00,pthread00}
	sudo ./test/zdtm.py run \
		-t zdtm/static/env00 \
		-t zdtm/static/pthread00 \
		-f h --rootless

	# Run it as non-root in a user namespace.  Since
	# CAP_CHECKPOINT_RESTORE behaves differently in non-user
	# namespaces (e.g. no access to map_files) this tests that we
	# can dump and restore under those conditions.
	# Note: the "... && true" part is necessary so that bash does
	# not exec the last statement and still reaps zombies.
	# Note: selinux in Enforcing mode prevents clone3() or
	# writing to ns_last_pid on restore; set to Permissive for
	# the test and then restore it.
	# Remove dump directory left by previous test runs as root;
	# the user namespace test runs as nobody (uid 65534) and
	# cannot write into root-owned directories.
	rm -rf test/dump
	selinuxmode=$(getenforce)
	sudo setenforce Permissive
	unshare --map-auto -fpm --mount-proc bash -c \
		"./test/zdtm.py run -t zdtm/static/maps00 -f h --rootless && true"
	sudo setenforce "$selinuxmode"
}

"$@"
