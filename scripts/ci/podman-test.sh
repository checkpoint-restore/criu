#!/bin/bash
set -x -e -o pipefail

export SKIP_CI_TEST=1

./run-ci-tests.sh

cd ../../

make install PREFIX=/usr

criu --version

# Install crun build dependencies
scripts/ci/apt-install libyajl-dev libseccomp-dev libsystemd-dev

# Install crun from source to test libcriu integration
tmp_dir=$(mktemp -d -t ci-XXXXXXXXXX)
pushd "${tmp_dir}"
git clone --depth=1 https://github.com/containers/crun
cd crun
./autogen.sh && ./configure --prefix=/usr
make -j"$(nproc)"
make install
popd
rm -rf "${tmp_dir}"

# overlayfs with current Ubuntu kernel breaks CRIU
# https://bugs.launchpad.net/ubuntu/+source/linux-azure/+bug/1967924
# Use VFS storage drive as a work-around
export STORAGE_DRIVER=vfs
podman --storage-driver vfs info

# shellcheck disable=SC2016
podman run --name cr -d docker.io/library/alpine /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'

sleep 1
for i in $(seq 20); do
	echo "Test $i for podman container checkpoint"
	podman exec cr ps axf
	podman logs cr
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "1" ]
	podman container checkpoint cr
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "0" ]
	podman ps -a
	podman container restore cr
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "1" ]
	podman logs cr
done

for i in $(seq 20); do
	echo "Test $i for podman container checkpoint --export"
	podman ps -a
	podman exec cr ps axf
	podman logs cr
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "1" ]
	podman container checkpoint -l --export /tmp/chkpt.tar.gz
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "0" ]
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "1" ]
	podman container restore --name cr2 --import /tmp/chkpt.tar.gz
	[ "$(podman ps -f name=cr2 -q -f status=running | wc -l)" -eq "1" ]
	podman ps -a
	podman logs cr
	podman logs cr2
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ "$(podman ps -f name=cr -q -f status=running | wc -l)" -eq "1" ]
	podman ps -a
	rm -f /tmp/chkpt.tar.gz
done
