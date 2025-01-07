#!/bin/bash

source ../../../functions.sh || exit 1
source ../../../env.sh || exit 1

cleanup_class() {
	rm -f ./*.class
}

javac HelloWorld.java || exit 1

set -x

rm -rf dump
mkdir dump

setsid java HelloWorld &

pid=${!}

echo Launched java application with pid $pid in background

${criu} dump -D dump -o dump.log -v4 --shell-job -t ${pid} || {
	echo "Dump failed"
	exit 1
}

wait_tasks dump

echo "Dumped, restoring and waiting for completion"

${criu} restore -D dump -o restore.log -v4 --shell-job || {
	echo "Restore failed"
	exit 1
}

echo PASS
