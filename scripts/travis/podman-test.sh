#!/bin/bash
set -x -e -o pipefail

add-apt-repository -y ppa:projectatomic/ppa

apt-get install -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

apt-get update -qq

apt-get install -qqy podman

export SKIP_TRAVIS_TEST=1

./travis-tests

cd ../../

make install

podman info

criu --version

podman run --name cr -d docker.io/library/alpine /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'

sleep 1
for i in `seq 50`; do
	echo "Test $i for podman container checkpoint"
	podman exec cr ps axf
	podman logs cr
	[ `podman ps -f name=cr -q | wc -l` -eq "1" ]
	podman container checkpoint cr
	[ `podman ps -f name=cr -q | wc -l` -eq "0" ]
	podman ps -a
	podman container restore cr
	[ `podman ps -f name=cr -q | wc -l` -eq "1" ]
	podman logs cr
done

for i in `seq 50`; do
	echo "Test $i for podman container checkpoint --export"
	podman ps -a
	podman exec cr ps axf
	podman logs cr
	[ `podman ps -f name=cr -q | wc -l` -eq "1" ]
	podman container checkpoint -l --export /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q | wc -l` -eq "0" ]
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q | wc -l` -eq "1" ]
	podman container restore --name cr2 --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr2 -q | wc -l` -eq "1" ]
	podman ps -a
	podman logs cr
	podman logs cr2
	podman ps -a
	podman rm -fa
	podman ps -a
	podman container restore --import /tmp/chkpt.tar.gz
	[ `podman ps -f name=cr -q | wc -l` -eq "1" ]
	podman ps -a
	rm -f /tmp/chkpt.tar.gz
done
