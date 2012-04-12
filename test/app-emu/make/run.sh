#!/bin/bash

crtools="../../../crtools"

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

echo Lanuched make in $pid background
sleep 2

${crtools} dump -D dump -o dump.log -v 4  -t ${pid} || {
	echo "Dump failed"
	exit 1
}

echo "Dumped, restoring and waiting for completion"

${crtools} restore -D dump -o restore.log -v 4 -t ${pid} || {
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
