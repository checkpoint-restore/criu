#!/bin/bash

# This script runs inside Lima VMs to set up and run CI tests.
# It is invoked with a command name, e.g.:
#   lima.sh centos-stream-setup
#   lima.sh centos-stream-test
#   lima.sh fedora-stable-setup
#   lima.sh fedora-stable-test
#   lima.sh fedora-next-setup
#   lima.sh fedora-next-test

set -e
set -x

CRIU_DIR="${CRIU_DIR:-/home/criu}"

centos-stream-setup() {
	# Enable CRB repository
	dnf config-manager --set-enabled crb
	# Install EPEL
	dnf -y install epel-release
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

	cd "${CRIU_DIR}"
	make -C scripts/ci local \
		SKIP_CI_PREP=1 CC=gcc CD_TO_TOP=1 \
		ZDTM_OPTS="-x zdtm/static/socket-raw"
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

"$@"
