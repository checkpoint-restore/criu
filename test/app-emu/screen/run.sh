#!/bin/bash

source ../../functions.sh || exit 1

crtools="../../../crtools"

set -x

echo "Creating reference objects"

screen -d -m -S crtools-zdtm
pid=$(screen -list | grep '\<crtools-zdtm\>.*Detached' | sed 's/\s*\([0-9]*\).*/\1/');
echo PID=$pid

mkdir dump

${crtools} dump -D dump -o dump.log -v 4  -t ${pid} || {
	echo "Dump failed"
	exit 1
}

wait_tasks dump

echo "Dumped, restoring and waiting for completion"

${crtools} restore -d -D dump -o restore.log -v 4 || {
	echo "Restore failed"
	exit 1
}

echo PASS
