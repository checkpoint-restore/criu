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

# docker checkpoint and restore is an experimental feature
echo '{ "experimental": true }' > /etc/docker/daemon.json
service docker restart

CRIU_LOG='/criu.log'
mkdir -p /etc/criu
echo "log-file=$CRIU_LOG" > /etc/criu/runc.conf

export SKIP_CI_TEST=1

./run-ci-tests.sh

cd ../../

make install

docker info

criu --version

run_container () {
	docker run \
		--tmpfs /tmp \
		--tmpfs /run \
		--read-only \
		--name cr \
		--health-cmd='sleep 1' \
		--health-interval=1s \
		-d \
		alpine \
		/bin/sh -c 'i=0; while true; do echo $i; i=$(expr $i + 1); sleep 1; done'
}

wait_running () {
	until [ "$(docker inspect -f '{{.State.Running}}' cr)" = "true" ]; do
		sleep 1;
	done;
}

wait_healthy () {
	until [ "$(docker inspect -f '{{.State.Health.Status}}' cr)" = "healthy" ]; do
		sleep 1;
	done;
}

checkpoint_container () {
	CHECKPOINT_NAME=$1

	docker checkpoint create cr "$CHECKPOINT_NAME" &&
	(docker exec cr true >> /dev/null 2>&1 && exit 1 || exit 0) &&
	# wait for container to stop
	docker wait cr
}

restore_container () {
	CHECKPOINT_NAME=$1

	docker start --checkpoint "$CHECKPOINT_NAME" cr 2>&1 | tee log || {
	cat "$(grep log 'log file:' | sed 's/log file:\s*//')" || true
		docker logs cr || true
		cat $CRIU_LOG || true
		dmesg
		docker ps
		exit 1
	}
}

# Scenario: Create multiple containers and checkpoint and restore them once
for i in $(seq 10); do
	run_container
	wait_running

	docker ps
	checkpoint_container checkpoint

	docker ps
	restore_container checkpoint

	docker ps
	docker rm -f cr
done

# Scenario: Create container and checkpoint and restore it multiple times
run_container
wait_running

for i in $(seq 5); do
	docker ps
	checkpoint_container checkpoint"${i}"

	docker ps
	restore_container checkpoint"${i}"

	# Wait for healthy state before creating another checkpoint
	wait_healthy
done
