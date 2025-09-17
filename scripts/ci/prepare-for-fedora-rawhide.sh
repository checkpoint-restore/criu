#!/bin/bash
set -e -x

COMMON_PACKAGES_LIST_FILE="${1:-contrib/dependencies/dnf-packages.txt}"

# SC2046 is "Quote this to prevent word splitting". We do want word splitting
# so that each line is passed as a separate argument
# shellcheck disable=SC2046
dnf install -y \
	diffutils \
	findutils \
	gawk \
	gcc \
	git \
	gnutls-devel \
	gzip \
	iproute \
	iptables \
	nftables \
	nftables-devel \
	libaio-devel \
	libasan \
	libcap-devel \
	libnet-devel \
	libnl3-devel \
	libbsd-devel \
	libselinux-utils \
	make \
	procps-ng \
	protobuf-c-devel \
	protobuf-devel \
	python3-PyYAML \
	python3-protobuf \
	python3-pip \
	python3-importlib-metadata \
	python-unversioned-command \
	redhat-rpm-config \
	sudo \
	tar \
	which \
	e2fsprogs \
	rubygem-asciidoctor \
	libdrm-devel \
	libuuid-devel \
	kmod \
	$(sed 's/\#.*$//' "${COMMON_PACKAGES_LIST_FILE}")

# /tmp is no longer 755 in the rawhide container image and breaks CI - fix it
chmod 1777 /tmp
