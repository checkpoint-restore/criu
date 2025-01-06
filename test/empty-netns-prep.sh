#!/bin/bash

set -ex

if [ "$CRTOOLS_SCRIPT_ACTION" == "setup-namespaces" ]; then
	echo "Will up lo at $CRTOOLS_INIT_PID netns"
	mkdir -p /var/run/netns
	mount -t tmpfs xxx /var/run/netns
	touch /var/run/netns/emptyns
	mount --bind /proc/$CRTOOLS_INIT_PID/ns/net /var/run/netns/emptyns
	ip netns exec emptyns ip link set up dev lo || exit 1
	ip netns exec emptyns ip a
	umount -l /var/run/netns
fi

exit 0
