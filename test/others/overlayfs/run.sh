#!/bin/bash

set -eu

CRIU=../../../criu/criu

setup() {
	setup_mount
	setsid sleep 10 3>z/file < /dev/null &> output &
	PROC_PID=$!
	echo "PROC_PID=$PROC_PID"
	sleep 1
}

setup_mount() {
	mkdir -p overlay_test
	cd overlay_test
	mkdir -p a b c z checkpoint
	mount -t overlay -o lowerdir=a,upperdir=b,workdir=c overlayfs z
}

check_criu() {
	echo "Dumping $PROC_PID..."
	if ! $CRIU dump -D checkpoint -t "${PROC_PID}"; then
		echo "ERROR! dump failed"
		return 1
	fi

	echo "Restoring..."
	if ! $CRIU restore -d -D checkpoint; then
		echo "ERROR! restore failed"
		return 1
	fi
	return 0
}

cleanup() {
	kill -INT "${PROC_PID}" > /dev/null 2>&1
	umount z
	cd "${ORIG_WD}"
	rm -rf overlay_test
}

main() {
	ORIG_WD=$(pwd)
	setup

	check_criu || {
		cleanup
		exit 1
	}

	cleanup
	echo "OverlayFS C/R successful."
	exit 0
}

main
