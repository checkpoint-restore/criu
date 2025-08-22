#!/usr/bin/env sh

APT_INSTALL="$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/apt-install"
if [ ! -x "$APT_INSTALL" ]; then
	echo "Error: apt-install not found or not executable"
	exit 1
fi

"$APT_INSTALL" \
	asciidoctor \
	bash \
	bsdmainutils \
	build-essential \
	gdb \
	git-core \
	iptables \
	kmod \
	libaio-dev \
	libbsd-dev \
	libcap-dev \
	libdrm-dev \
	libelf-dev \
	libgnutls28-dev \
	libgnutls30 \
	libnet-dev \
	libnl-3-dev \
	libnl-route-3-dev \
	libperl-dev \
	libprotobuf-c-dev \
	libprotobuf-dev \
	libselinux-dev \
	libtraceevent-dev \
	libtracefs-dev \
	pkg-config \
	protobuf-c-compiler \
	protobuf-compiler \
	python3-importlib-metadata \
	python3-pip \
	python3-protobuf \
	python3-yaml \
	time \
	util-linux \
	uuid-dev
