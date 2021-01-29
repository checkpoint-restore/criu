#!/bin/bash

# This script is used to run vagrant based tests on Travis.
# This script is started via sudo from .travis.yml

set -e
set -x

VAGRANT_VERSION=2.2.14
FEDORA_VERSION=33
FEDORA_BOX_VERSION=33.20201019.0

setup() {
	if [ -n "$TRAVIS" ]; then
		# Load the kvm modules for vagrant to use qemu
		modprobe kvm kvm_intel
	fi
	if [ -n "$CIRRUS_CI" ]; then
		# Running modprobe is not possible on Cirrus, because
		# we are running in a container with potentially other
		# modules than the host.
		# Vagrant can still use /dev/kvm later if we do
		chmod 666 /dev/kvm
	fi

	# Tar up the git checkout to have vagrant rsync it to the VM
	tar cf criu.tar ../../../criu
	# Cirrus has problems with the following certificate.
	wget --no-check-certificate https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}_"$(uname -m)".deb -O /tmp/vagrant.deb && \
		dpkg -i /tmp/vagrant.deb

	./apt-install libvirt-clients libvirt-daemon-system libvirt-dev qemu-utils qemu \
		ruby build-essential libxml2-dev qemu-kvm rsync ebtables dnsmasq-base \
		openssh-client
	if [ -n "$CIRRUS_CI" ]; then
		# On Cirrus systemctl does not work, because we are running in
		# a container without access to systemd
		/usr/sbin/virtlogd -d
		/usr/sbin/libvirtd -d
	else
		systemctl restart libvirtd
	fi
	vagrant plugin install vagrant-libvirt
	vagrant init fedora/${FEDORA_VERSION}-cloud-base --box-version ${FEDORA_BOX_VERSION}
	# The default libvirt Vagrant VM uses 512MB.
	# Travis VMs should have around 7.5GB.
	# Increasing it to 4GB should work.
	sed -i Vagrantfile -e 's,^end$,  config.vm.provider :libvirt do |libvirt|'"\n"'    libvirt.memory = 4096;end'"\n"'end,g'
	if [ -n "$CIRRUS_CI" ]; then
		# Work around for:
		# Error while activating network: Call to virNetworkCreate failed: internal error:
		# Failed to apply firewall rules /usr/sbin/ip6tables --table filter --list-rules: modprobe: FATAL: Module ip6_tables not found in directory /lib/modules/5.4.0-1025-gcp
		# On cirrus-ci.com. Running in a container without access to the host's kernel modules
		rm -f /sbin/ip6tables
		cp /bin/true /sbin/ip6tables
	fi
	vagrant up --provider=libvirt --no-tty
	mkdir -p /root/.ssh
	vagrant ssh-config >> /root/.ssh/config
	ssh default sudo dnf upgrade -y
	ssh default sudo dnf install -y gcc git gnutls-devel nftables-devel libaio-devel \
		libasan libcap-devel libnet-devel libnl3-devel make protobuf-c-devel \
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
}

$1
