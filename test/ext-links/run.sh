#!/bin/bash

ip=${CR_IP_TOOL:-xip}
mvln="mv0"
finf="finish"
outf="ns_output"
pidf="ns_pid"
criu="../../criu"

export ip
export mvln
export finf
export outf
export pidf

function fail {
	$ip link del $mvln
	touch $finf
	echo $@
	exit 1
}

# Build the mvlink plugin
make

set -x

rm -f "$finf" "$outf" "$pidf"
rm -rf "dump"

# Unshare netns. The run_ns will exit once ns is spawned.
unshare --net ./run_ns.sh
nspid=$(cat $pidf)
ps $nspid

# Create and push macvlan device into it. CRIU doesn't support
# macvlans treating them as external devices.
./addmv_raw.sh $mvln $nspid || fail "Can't setup namespace"

# Dump
sleep 1
mkdir dump
$criu dump -t $nspid -D dump/ -o dump.log -v4 --lib $(pwd) || fail "Can't dump namespace"

# Restore
# Ask for the pid (shouldn't change, so just as an example), ask to call
# script that will put macvlan device back into namespace
sleep 1
rm -f $pidf
$criu restore -D dump/ -o restore.log -v4 --pidfile $(pwd)/$pidf --action-script "$(pwd)/addmv.sh $mvln $(pwd)/$pidf" -d || fail "Can't restore namespaces"

# Finish and check results
touch $finf
set +x
while ! egrep 'PASS|FAIL' $outf; do
	echo "Waiting"
	sleep 1
done
