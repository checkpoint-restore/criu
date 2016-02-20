#!/bin/bash

echo "Wait: $$"
while [ ! -e "$finf" ]; do
	echo "WAIT ($$)"
	sleep 1;
done

echo "Links after:"
$ip link list

# The mvln device (exported from run.sh) should exits in
# namespace after we get restored
echo "Check for $mvln:"
$ip link list $mvln && echo "PASS" || echo "FAIL"
