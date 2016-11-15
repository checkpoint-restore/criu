#!/bin/sh

if [ "$CRTOOLS_SCRIPT_ACTION" == "setup-namespaces" ]; then
	echo "Will up lo at $CRTOOLS_INIT_PID netns"
	nsenter -t "$CRTOOLS_INIT_PID" --net ip link set up dev lo || exit 1
fi

exit 0
