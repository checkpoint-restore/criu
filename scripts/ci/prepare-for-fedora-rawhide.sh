#!/bin/bash
set -e -x

dnf install -y \
	diffutils \
	findutils \
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
	make \
	procps-ng \
	protobuf-c-devel \
	protobuf-devel \
	python3-flake8 \
	python3-PyYAML \
	python3-future \
	python3-protobuf \
	python3-junit_xml \
	python-unversioned-command \
	redhat-rpm-config \
	sudo \
	tar \
	which \
	e2fsprogs \
	rubygem-asciidoctor \
	kmod

# /tmp is no longer 755 in the rawhide container image and breaks CI - fix it
chmod 1777 /tmp
