#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
CRIU="${SCRIPT_DIR}/../../../criu/criu"
ORIG_WD=$(pwd)
PROC_PID=""

cleanup() {
	if [ -n "${PROC_PID}" ]; then
		kill "${PROC_PID}" > /dev/null 2>&1 || true
		wait "${PROC_PID}" 2>/dev/null || true
	fi
	cd "${ORIG_WD}"
	umount ovl_inotify/merged 2>/dev/null || true
	rm -rf ovl_inotify
}

trap cleanup EXIT

setup() {
	mkdir -p ovl_inotify
	cd ovl_inotify
	mkdir -p lower upper work merged checkpoint

	cp "${SCRIPT_DIR}/inotify_test" .
	touch lower/testfile
	mount -t overlay overlay \
		-o lowerdir=lower,upperdir=upper,workdir=work merged

	setsid bash -c 'echo $$ > inotify.pid; exec ./inotify_test "$@"' \
		-- merged/testfile < /dev/null &> output &
	sleep 1
	PROC_PID=$(cat inotify.pid)
	echo "PROC_PID=$PROC_PID"
}

check_criu() {
	echo "Dumping $PROC_PID..."
	if ! $CRIU dump -D checkpoint -t "${PROC_PID}" --shell-job -v4; then
		echo "ERROR! dump failed"
		return 1
	fi

	echo "Restoring..."
	if ! $CRIU restore -d -D checkpoint --shell-job -v4; then
		echo "ERROR! restore failed"
		return 1
	fi

	sleep 1

	# Trigger an inotify event on the restored process
	touch merged/testfile
	sleep 1

	# The restored process should still be alive
	if ! kill -0 "${PROC_PID}" 2>/dev/null; then
		echo "ERROR! restored process is not running"
		return 1
	fi

	return 0
}

main() {
	setup

	if ! check_criu; then
		exit 1
	fi

	echo "OverlayFS inotify C/R successful."
	exit 0
}

main
