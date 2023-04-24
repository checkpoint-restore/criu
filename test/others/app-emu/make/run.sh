#!/bin/bash

source ../../functions.sh || exit 1
source ../../env.sh || exit 1

cleanup_wd() {
	rm -f "ref-*"
	make clean
}

set -x

echo "Creating reference objects"

cleanup_wd

setsid make || exit 1

for f in *.o; do
	mv "$f" "ref-${f//.o/}";
done

rm -rf dump
mkdir dump

setsid make clean || exit 1
setsid make -j4 &

pid=${!}

echo Launched make in $pid background
sleep 2

${criu} dump --shell-job -D dump -o dump.log -v4  -t ${pid} || {
	echo "Dump failed"
	exit 1
}

wait_tasks dump

echo "Dumped, restoring and waiting for completion"

${criu} restore --shell-job -D dump -o restore.log -v4 || {
	echo "Restore failed"
	exit 1
}

for f in ref-*; do
	if ! cmp "$f" "${f//ref-/}.o"; then
		echo "$f mismatch"
		echo "FAIL"
		cleanup_wd
		exit 1
	fi
done

cleanup_wd

echo PASS
