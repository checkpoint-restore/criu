#!/bin/bash

# shellcheck disable=SC1091,SC2015

set -x -e -o pipefail

./apt-install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable test"

./apt-install docker-ce

. /etc/lsb-release

echo '{ "experimental": true }' > /etc/docker/daemon.json

CRIU_LOG='/criu.log'
mkdir -p /etc/criu
echo "log-file=$CRIU_LOG" > /etc/criu/runc.conf

service docker stop
systemctl stop containerd.service

# Always use the latest containerd release.
# Restore with containerd versions after v1.2.14 and before v1.5.0-beta.0 are broken.
# https://github.com/checkpoint-restore/criu/issues/1223
CONTAINERD_DOWNLOAD_URL=$(curl -s https://api.github.com/repos/containerd/containerd/releases/latest | grep '"browser_download_url":.*/containerd-.*-linux-amd64.tar.gz.$' | cut -d\" -f4)
wget -nv "$CONTAINERD_DOWNLOAD_URL" -O - | tar -xz -C /usr/

systemctl restart containerd.service
service docker restart

export SKIP_CI_TEST=1

./run-ci-tests.sh

cd ../../

make install

docker info

criu --version

# shellcheck disable=SC2016
docker run --tmpfs /tmp --tmpfs /run --read-only --security-opt seccomp=unconfined --name cr -d alpine /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'

sleep 1
for i in $(seq 50); do
	# docker start returns 0 silently if a container is already started
	# docker checkpoint doesn't wait when docker updates a container state
	# Due to both these points, we need to sleep after docker checkpoint to
	# avoid races with docker start.
	docker exec cr ps axf &&
	docker checkpoint create cr checkpoint"$i" &&
	sleep 1 &&
	docker ps &&
	(docker exec cr true && exit 1 || exit 0) &&
	docker start --checkpoint checkpoint"$i" cr 2>&1 | tee log || {
	cat "$(grep log 'log file:' | sed 's/log file:\s*//')" || true
		docker logs cr || true
		cat $CRIU_LOG || true
		dmesg
		docker ps
		exit 1
	}
	docker ps
	sleep 1
done

