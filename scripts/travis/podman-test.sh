#!/bin/bash
set -x -e -o pipefail

echo 'deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list

wget -nv https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_18.04/Release.key -O- | apt-key add -

# podman conflicts with a man page from docker-ce
# this is a podman packaging bug (https://github.com/containers/libpod/issues/4747)
apt-get -y purge docker-ce

apt-get install -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

apt-get update -qq
apt-get install -qqy podman containernetworking-plugins

export SKIP_TRAVIS_TEST=1

./travis-tests

cd ../../

make install

# overlaysfs behaves differently on Ubuntu and breaks CRIU
# https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1857257
podman --storage-driver vfs info

criu --version

podman run --name cr -d docker.io/library/alpine /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'

sleep 1
for i in `seq 20`; do
	echo "Test $i for podman container checkpoint"
	podman exec cr ps axf
	podman logs cr
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "1" ]
	podman container checkpoint cr
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "0" ]
	podman ps -a
	podman container restore cr
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "1" ]
	podman logs cr
done

for i in `seq 20`; do
	echo "Test $i for podman container checkpoint --export"
	podman ps -a
	podman exec cr ps axf
	podman logs cr
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "1" ]
	podman container checkpoint -l --export /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "0" ]
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "1" ]
	podman container restore --name cr2 --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr2 -q -f status=running | wc -l` -eq "1" ]
	podman ps -a
	podman logs cr
	podman logs cr2
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q -f status=running | wc -l` -eq "1" ]
	podman ps -a
	rm -f /tmp/chkpt.tar.gz
done
