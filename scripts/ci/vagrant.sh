#!/bin/bash

# This script is used to run vagrant based tests on Cirrus CI.
# This script is started via .cirrus.yml

set -e
set -x

VAGRANT_VERSION=2.2.19
FEDORA_VERSION=35
FEDORA_BOX_VERSION=35.20211026.0

setup() {
	if [ -n "$TRAVIS" ]; then
		# Load the kvm modules for vagrant to use qemu
		modprobe kvm kvm_intel
	fi

	# Tar up the git checkout to have vagrant rsync it to the VM
	tar cf criu.tar ../../../criu
	# Cirrus has problems with the following certificate.
	wget --no-check-certificate https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}_"$(uname -m)".deb -O /tmp/vagrant.deb && \
		dpkg -i /tmp/vagrant.deb

	./apt-install libvirt-clients libvirt-daemon-system libvirt-dev qemu-utils qemu \
		ruby build-essential libxml2-dev qemu-kvm rsync ebtables dnsmasq-base \
		openssh-client
	systemctl restart libvirtd
	vagrant plugin install vagrant-libvirt
	vagrant init fedora/${FEDORA_VERSION}-cloud-base --box-version ${FEDORA_BOX_VERSION}
	# The default libvirt Vagrant VM uses 512MB.
	# Travis VMs should have around 7.5GB.
	# Increasing it to 4GB should work.
	sed -i Vagrantfile -e 's,^end$,  config.vm.provider :libvirt do |libvirt|'"\n"'    libvirt.memory = 4096;end'"\n"'end,g'
	vagrant up --provider=libvirt --no-tty
	mkdir -p /root/.ssh
	vagrant ssh-config >> /root/.ssh/config
	ssh default sudo dnf upgrade -y
	ssh default sudo dnf install -y gcc git gnutls-devel nftables-devel libaio-devel \
		libasan libcap-devel libnet-devel libnl3-devel libbsd-devel make protobuf-c-devel \
		protobuf-devel python3-flake8 python3-future python3-protobuf \
		python3-junit_xml rubygem-asciidoctor iptables libselinux-devel libbpf-devel
	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
	ssh default sudo systemctl mask sssd
	ssh default cat /proc/cmdline
}

fedora-no-vdso() {
	ssh default sudo grubby --update-kernel ALL --args="vdso=0"
	vagrant reload
	ssh default cat /proc/cmdline
	ssh default 'cd /vagrant; tar xf criu.tar; cd criu; make -j 4'
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -a --keep-going'
	# This test (pidfd_store_sk) requires pidfd_getfd syscall which is guaranteed in Fedora 33.
	# It is also skipped from -a because it runs in RPC mode only
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -t zdtm/transition/pidfd_store_sk --rpc --pre 2'
}

fedora-rawhide() {
	#
	# Workaround the problem:
	# error running container: error from /usr/bin/crun creating container for [...]: sd-bus call: Transport endpoint is not connected
	# Let's just use runc instead of crun
	# see also https://github.com/kata-containers/tests/issues/4283
	#
	ssh default 'sudo dnf remove -y crun || true'
	ssh default sudo dnf install -y podman runc
	ssh default 'cd /vagrant; tar xf criu.tar; cd criu; sudo -E make -C scripts/ci fedora-rawhide CONTAINER_RUNTIME=podman BUILD_OPTIONS="--security-opt seccomp=unconfined"'
}

$1
