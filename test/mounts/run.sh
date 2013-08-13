#!/bin/bash

CRIU=../../criu
set -x

mkdir -p dump

./mounts.sh
pid=`cat mounts.pid`
kill -0 $pid || exit

cat /proc/$pid/mountinfo | sort -k 4
echo "Suspend server"
${CRIU} dump -D dump -o dump.log -t $pid -v4 || {
	cat dump/dump.log | grep Error
	exit 1
}
echo "Resume server"
${CRIU} restore -d -D dump -o restore.log -v4 || {
	cat dump/dump.log | grep Error
	exit 1
}
cat /proc/$pid/mountinfo | sort -k 4
kill $pid
