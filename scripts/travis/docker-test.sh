#!/bin/bash
set -x -e -o pipefail

apt-get install -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"


apt-get update -qq

apt-get install -qq docker-ce

cat > /etc/docker/daemon.json <<EOF
{
    "experimental": true
}
EOF

service docker restart

export SKIP_TRAVIS_TEST=1

./travis-tests

cd ../../

make install

docker info

criu --version

docker run --tmpfs /tmp --tmpfs /run --read-only --security-opt=seccomp:unconfined --name cr -d alpine /bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'

sleep 1
for i in `seq 50`; do
	# docker start returns 0 silently if a container is already started
	# docker checkpoint doesn't wait when docker updates a container state
	# Due to both these points, we need to sleep after docker checkpoint to
	# avoid races with docker start.
	docker exec cr ps axf &&
	docker checkpoint create cr checkpoint$i &&
	sleep 1 &&
	docker start --checkpoint checkpoint$i cr 2>&1 | tee log || {
		cat "`cat log | grep 'log file:' | sed 's/log file:\s*//'`" || true
		docker logs cr || true
		cat /tmp/zdtm-core-* || true
		dmesg
		docker ps
		exit 1
	}
	docker ps
	sleep 1
done

