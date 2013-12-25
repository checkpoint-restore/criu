#!/bin/bash

echo $$ > $pidfile

echo "My mounts (before)"
cat "/proc/self/mountinfo"

while [ ! -e "$finf" ]; do
	echo "WAIT"
	sleep 1;
done

echo "My mounts (after)"
cat "/proc/self/mountinfo"

if fgrep "$2" "$1" ; then
	echo "PASS"
else
	echo "FAIL"
fi
