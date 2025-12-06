#!/usr/bin/env sh

APT_INSTALL="$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/apt-install"
if [ ! -x "$APT_INSTALL" ]; then
	echo "Error: apt-install not found or not executable"
	exit 1
fi

"$APT_INSTALL" \
	crossbuild-essential-"${DEBIAN_ARCH}" \
	iproute2:"${DEBIAN_ARCH}" \
	libaio-dev:"${DEBIAN_ARCH}" \
	libbz2-dev:"${DEBIAN_ARCH}" \
	libc6-"${DEBIAN_ARCH}"-cross \
	libc6-dev-"${DEBIAN_ARCH}"-cross \
	libcap-dev:"${DEBIAN_ARCH}" \
	libdrm-dev:"${DEBIAN_ARCH}" \
	libelf-dev:"${DEBIAN_ARCH}" \
	libexpat1-dev:"${DEBIAN_ARCH}" \
	libgnutls28-dev:"${DEBIAN_ARCH}" \
	libnet-dev:"${DEBIAN_ARCH}" \
	libnftables-dev:"${DEBIAN_ARCH}" \
	libnl-3-dev:"${DEBIAN_ARCH}" \
	libnl-route-3-dev:"${DEBIAN_ARCH}" \
	libprotobuf-c-dev:"${DEBIAN_ARCH}" \
	libprotobuf-dev:"${DEBIAN_ARCH}" \
	libssl-dev:"${DEBIAN_ARCH}" \
	libtraceevent-dev:"${DEBIAN_ARCH}" \
	libtracefs-dev:"${DEBIAN_ARCH}" \
	ncurses-dev:"${DEBIAN_ARCH}" \
	uuid-dev:"${DEBIAN_ARCH}" \
	build-essential \
	pkg-config \
	git \
	protobuf-c-compiler \
	protobuf-compiler \
	python3-protobuf
