#!/bin/bash

# This script is used to run vagrant based tests on Travis.
# This script is started via sudo from .travis.yml

set -e
set -x

VAGRANT_VERSION=2.2.10
FEDORA_VERSION=32
FEDORA_BOX_VERSION=32.20200422.0

setup() {
	chmod 666 /dev/kvm
	ls -la /dev
	apt-get -qq update
	# Load the kvm modules for vagrant to use qemu
	lsmod || :
	modprobe kvm kvm_intel || :
	printenv

	# Tar up the git checkout to have vagrant rsync it to the VM
	tar cf criu.tar ../../../criu
	wget --no-check-certificate https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}_"$(uname -m)".deb -O /tmp/vagrant.deb && \
		dpkg -i /tmp/vagrant.deb

	./apt-install libvirt-clients libvirt-daemon-system libvirt-dev qemu-utils qemu \
		ruby build-essential libxml2-dev qemu-kvm rsync ebtables dnsmasq-base \
		openssh-client
	systemctl restart libvirtd || :
	/usr/sbin/libvirtd -d
	/usr/sbin/virtlogd -d
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
		#ls -la /usr/sbin/ip6tables
		#rm -f /usr/sbin/ip6tables
		#rm -f /sbin/ip6tables
		#rm -f /etc/alternatives/ip6tables
		#rm -f /usr/sbin/ip6tables-legacy
		#cp /bin/true /usr/sbin/ip6tables
		#cp /bin/true /sbin/ip6tables
		#cp /bin/true /etc/alternatives/ip6tables
		#cp /bin/true /usr/sbin/ip6tables-legacy
		#ls -la /usr/sbin/ip6tables
		ls -la /sbin/ip6tables
		rm -f /sbin/ip6tables
		cp /bin/true /sbin/ip6tables
		cat /etc/libvirt/qemu/networks/default.xml
	fi
	vagrant up --provider=libvirt > /dev/null
	mkdir -p /root/.ssh
	vagrant ssh-config >> /root/.ssh/config
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
	# Excluding two cgroup tests which seem to fail because of cgroup2
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -a --keep-going'
}

$1
