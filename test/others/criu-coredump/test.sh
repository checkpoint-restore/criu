#!/bin/bash

set -x
# shellcheck source=test/others/env.sh
source ../env.sh || exit 1

function gen_imgs {
	PID=$(../loop with a very very very very very very very very very very very very long cmdline)
	if ! $CRIU dump -v4 -o dump.log -D ./ -t "$PID"; then
		echo "Failed to checkpoint process $PID"
		cat dump.log
		kill -9 "$PID"
		exit 1
	fi

	images_list=$(ls -1 ./*.img)
	if [ -z "$images_list" ]; then
		echo "Failed to generate images"
		exit 1
	fi
}

function run_test {
	echo "= Test core dump"

	echo "=== img to core dump"
	$CRIU_COREDUMP -i ./ -o ./ || exit $?
	echo "=== done"

	cores=$(ls -1 core.*)
	if [ -z "$cores" ]; then
		echo "Failed to generate coredumps"
		exit 1
	fi

	for x in $cores
	do
		echo "=== try readelf $x"
		readelf -a "$x" || exit $?
		echo "=== done"
	done

	echo "= done"
}

gen_imgs
run_test
