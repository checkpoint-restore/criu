#!/bin/bash

[ -z "$CR_IP_TOOL" ] && CR_IP_TOOL=ip

action=$1
shift

[[ "network-unlock" == "$CRTOOLS_SCRIPT_ACTION" ||
   "network-lock" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

set -o pipefail

[ "$action" == dump ] && {
	pid=$1
	name=$2

	# Find a pair of CT's eth0
	ifindex=`$CR_IP_TOOL netns exec $name ethtool -S eth0 | awk '/index/ { print $2}'`
	[ $? -eq 0 ] || exit 1

	for i in /sys/devices/virtual/net/*; do
		[ "`cat $i/ifindex`" == $ifindex ] && {
			dst=`basename $i`
			break;
		}
	done

	[ -z "$dst" ] && exit 1

	echo "$dst<=>eth0"

	[ "network-unlock" == "$CRTOOLS_SCRIPT_ACTION" ] && {
		echo Attach $dst to the bridge br0
		brctl addif br0 $dst
		exit $?
	}

	[ "network-lock" == "$CRTOOLS_SCRIPT_ACTION" ] && {
		echo Detach $dst to the bridge br0
		brctl delif br0 $dst
		exit $?
	}

	exit 0
}

[ "$action" == restore ] && {
	[ "network-unlock" == "$CRTOOLS_SCRIPT_ACTION" ] && {
		ethname=$1
		echo Attach $ethname to the bridge br0
		ip link set up dev $ethname
		brctl addif br0 $ethname
		exit $?
	}
}

exit 0
