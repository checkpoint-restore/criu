#!/bin/bash

crtools="../../../crtools"
DEPTH=3
SPAN=5
archref="arch-ref.tar.bz2"
archcr="arch.tar.bz2"

rm -f ${archref}
rm -f ${archcr}
rm -rf tree/
rm -rf dump/
mkdir dump
mkdir tree

echo "Generating tree, depth ${DEPTH} span ${SPAN}"

function gen_sub {
	local dir="${1}"
	local dep="${2}"

	for i in $(seq 1 $SPAN); do
		subdir="$dir/dir_$((RANDOM % 32))_$i"
		subfl="$dir/file_$((RANDOM % 32))_$i"

		mkdir "$subdir"
		dd if=/dev/urandom of=$subfl bs=4096 count=$((RANDOM % 32 + 16)) > /dev/null 2>&1

		if [ $dep -gt 0 ]; then
			gen_sub "$subdir" $((dep - 1))
		fi
	done
}

gen_sub "./tree/" "$DEPTH"

set -x

time tar cjf ${archref} tree || exit 1

setsid tar cjf ${archcr} tree &

pid=${!}

echo "Started tar in $pid background"
sleep 3

${crtools} dump -D dump -o dump.log -v 4 -t ${pid} || {
	echo "Dump failed"
	exit 1
}

echo "Dump OK, restoring"

${crtools} restore -D dump -o restore.log -v 4 -t ${pid} || {
	echo "Restore failed"
	exit 1
}

echo "Finished, comparing tarballs"

if ! cmp ${archref} ${archcr} ; then
	echo "Archives differ"
	echo "FAIL"
else
	echo "PASS"
	rm -f ${archref}
	rm -f ${archcr}
	rm -rf tree/
fi
