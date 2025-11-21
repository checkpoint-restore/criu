#!/bin/bash

set -x -e -o pipefail

# Workaround: Docker 28.x has a known regression that breaks the checkpoint and
# restore (C/R) feature. Let's install previous, or next major version. See
# https://github.com/moby/moby/issues/50750 for details on the bug.
export DEBIAN_FRONTEND=noninteractive
apt remove -y docker-ce docker-ce-cli
../../contrib/apt-install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
# shellcheck disable=SC1091
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" > /etc/apt/sources.list.d/docker.list
apt update -y
apt-cache madison docker-ce | awk '{ print $3 }'
verstr="$(apt-cache madison docker-ce | awk '{ print $3 }' | sort | grep -v ':28\.'| tail -n 1)"
../../contrib/apt-install -y "docker-ce=$verstr" "docker-ce-cli=$verstr"

# docker checkpoint and restore is an experimental feature
echo '{ "experimental": true }' > /etc/docker/daemon.json
service docker restart

CRIU_LOG='/criu.log'
mkdir -p /etc/criu
echo "log-file=$CRIU_LOG" > /etc/criu/runc.conf

# Test checkpoint/restore with action script
echo "action-script /usr/bin/true" | sudo tee /etc/criu/default.conf

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

print_logs () {
	# Show CRIU restore log if the path was printed in docker output.
	cat "$(grep -E 'log file:' log | sed -E 's/.*log file:\s*//')" || true
	docker logs cr || true
	cat "$CRIU_LOG" || true
	dmesg || true
	docker ps || true
	exit 1
}

# Increase retries to make the test robust against known containerd races.
declare -i max_restore_container_tries=6

restore_container () {
	CHECKPOINT_NAME=$1

	for i in $(seq $max_restore_container_tries); do
		# Small back-off before attempting the restore to avoid races
		sleep 1
		docker start --checkpoint "$CHECKPOINT_NAME" cr 2>&1 | tee log && return 0

		# Known transient errors observed across containerd/docker versions.
		if grep -Eq 'already exists' log || \
		   grep -Eq 'failed to upload checkpoint to containerd' log || \
		   grep -Eq 'context deadline exceeded' log || \
		   grep -Eq 'transport is closing' log; then
			echo "Retry container restore: $i/$max_restore_container_tries"
			continue
		fi

		print_logs

	done

	# If we are here, all retries were exhausted.
	print_logs
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
