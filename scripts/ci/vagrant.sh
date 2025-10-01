#!/bin/bash

# This script is used to run vagrant based tests on Cirrus CI.
# This script is started via .cirrus.yml

set -e
set -x

VAGRANT_VERSION=2.4.7
FEDORA_VERSION=42
FEDORA_BOX_VERSION=1.1.0

setup() {
	# Tar up the git checkout to have vagrant rsync it to the VM
	tar cf /tmp/criu.tar -C ../../../ criu
	# Cirrus has problems with the following certificate.
	wget --no-check-certificate https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}-1_"$(dpkg --print-architecture)".deb -O /tmp/vagrant.deb && \
		dpkg -i /tmp/vagrant.deb

	../../contrib/apt-install libvirt-clients libvirt-daemon-system libvirt-dev qemu-utils qemu-system \
		ruby build-essential libxml2-dev qemu-kvm rsync ebtables dnsmasq-base openssh-client
	systemctl restart libvirtd
	vagrant plugin install vagrant-libvirt
	vagrant init cloud-image/fedora-${FEDORA_VERSION} --box-version ${FEDORA_BOX_VERSION}

	# The default libvirt Vagrant VM uses 512MB.
	# VMs in our CI typically have around 16GB.
	# Increasing it to 4GB should work.
	sed -i Vagrantfile -e 's,^end$,  config.vm.provider :libvirt do |libvirt|'"\n"'    libvirt.memory = 4096;end'"\n"'end,g'
	# Sync /tmp/criu.tar into the VM
	# We want to use $HOME without expansion
	# shellcheck disable=SC2016
	sed -i Vagrantfile -e 's|^end$|  config.vm.provision "file", source: "/tmp/criu.tar", destination: "$HOME/criu.tar"'"\n"'end|g'

	vagrant up --provider=libvirt --no-tty
	mkdir -p /root/.ssh
	vagrant ssh-config >> /root/.ssh/config

	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
	ssh default sudo systemctl mask sssd

	ssh default 'sudo mkdir -p --mode=777 /vagrant && mv $HOME/criu.tar /vagrant && cd /vagrant && tar xf criu.tar'
	ssh default sudo dnf upgrade -y
	ssh default sudo /vagrant/criu/contrib/dependencies/dnf-packages.sh
	ssh default cat /proc/cmdline
}

fedora-no-vdso() {
	ssh default sudo grubby --update-kernel ALL --args="vdso=0"
	vagrant reload
	ssh default cat /proc/cmdline
	ssh default 'cd /vagrant/criu; make -j'
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -a --keep-going'
	# This test (pidfd_store_sk) requires pidfd_getfd syscall which is guaranteed in Fedora 33.
	# It is also skipped from -a because it runs in RPC mode only
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -t zdtm/transition/pidfd_store_sk --rpc --pre 2'
}

fedora-rawhide() {
	# Upgrade the kernel to the latest vanilla one
	ssh default sudo dnf -y copr enable @kernel-vanilla/stable
	ssh default sudo dnf upgrade -y

	# The 6.2 kernel of Fedora 38 in combination with rawhide userspace breaks
	# zdtm/static/socket-tcp-nfconntrack. To activate the new kernel previously
	# installed this reboots the VM.
	vagrant reload
	ssh default uname -a
	#
	# Workaround the problem:
	# error running container: error from /usr/bin/crun creating container for [...]: sd-bus call: Transport endpoint is not connected
	# Let's just use runc instead of crun
	# see also https://github.com/kata-containers/tests/issues/4283
	#
	ssh default 'sudo dnf remove -y crun || true'
	ssh default sudo dnf install -y podman runc
	# Some tests in the container need selinux to be disabled.
	# In the container it is not possible to change the state of selinux.
	# Let's just disable it for this test run completely.
	ssh default 'sudo setenforce Permissive'
	ssh default 'cd /vagrant/criu; sudo -E make -C scripts/ci fedora-rawhide CONTAINER_RUNTIME=podman BUILD_OPTIONS="--security-opt seccomp=unconfined"'
}

fedora-non-root() {
	ssh default uname -a
	ssh default 'cd /vagrant/criu; make -j'
	# Setting the capability should be the only line needed to run as non-root on Fedora
	# In other environments either set /proc/sys/kernel/yama/ptrace_scope to 0 or grant cap_sys_ptrace to criu
	ssh default 'sudo setcap cap_checkpoint_restore+eip /vagrant/criu/criu/criu'
	# Run it once as non-root
	ssh default 'cd /vagrant/criu; criu/criu check --unprivileged; ./test/zdtm.py run -t zdtm/static/env00 -t zdtm/static/pthread00 -f h --rootless'
	# Run it as root with '--rootless'
	ssh default 'cd /vagrant/criu; sudo ./test/zdtm.py run -t zdtm/static/env00 -t zdtm/static/pthread00 -f h; sudo chmod 777 test/dump/zdtm/static/{env00,pthread00}; sudo ./test/zdtm.py run -t zdtm/static/env00 -t zdtm/static/pthread00 -f h --rootless'
	# Run it as non-root in a user namespace. Since CAP_CHECKPOINT_RESTORE behaves differently in non-user namespaces (e.g. no access to map_files) this tests that we can dump and restore
	# under those conditions. Note that the "... && true" part is necessary; we need at least one statement after the tests so that bash can reap zombies in the user namespace,
	# otherwise it will exec the last statement and get replaced and nobody will be left to reap our zombies.
	# Note: selinux in Enforcing mode prevents us from calling clone3() or writing to ns_last_pid on restore; hence set to Permissive for the test and then set back.
	ssh default 'cd /vagrant/criu; selinuxmode=`getenforce` && sudo setenforce Permissive && unshare -Ucfpm --mount-proc bash -c "./test/zdtm.py run -t zdtm/static/maps00 -f h --rootless && true" && sudo setenforce $selinuxmode'
}

$1
