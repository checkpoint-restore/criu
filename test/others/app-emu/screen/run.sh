#!/bin/bash

source ../../functions.sh || exit 1
source ../../env.sh || exit 1

set -x

echo "Creating reference objects"

screen -d -m -S criu-zdtm
pid=$(screen -list | grep '\<criu-zdtm\>.*Detached' | sed 's/\s*\([0-9]*\).*/\1/');
echo PID=$pid

mkdir dump

${criu} dump -D dump -o dump.log -v4  -t ${pid} || {
	echo "Dump failed"
	exit 1
}

wait_tasks dump

echo "Dumped, restoring and waiting for completion"

${criu} restore -d -D dump -o restore.log -v4 || {
	echo "Restore failed"
	exit 1
}

echo PASS
