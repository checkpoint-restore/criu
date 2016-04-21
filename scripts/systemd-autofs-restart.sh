#!/bin/bash
#
# This script can be used as a workaround for systemd autofs mount migration.
# The problem is that systemd is a clever guy: before mounting of actual file
# system on top of autofs mount, it first checks that device number of autofs
# mount is equal to the one, stored in sytemd internals. If they do not match,
# systemd ignores kernel request.
# The problem happens each time autofs is restored (new device number for
# autofs superblock) and can't be properly solved without some kind of "device
# namespaces", where device number can be preseved.
# But some of systemd services can be painlessly restarted. Like
# proc-sys-fs-binfmt_misc.
#
# Usage:
# criu restore <options> --action-script $(pwd)/scripts/systemd-autofs-restart.sh
#
[ "$CRTOOLS_SCRIPT_ACTION" == "post-resume" ] || exit 0

if [ ! -n "$CRTOOLS_INIT_PID" ]; then
	echo "CRTOOLS_INIT_PID environment variable is not set"
	exit 1
fi

if [ ! -d "/proc/$CRTOOLS_INIT_PID" ]; then
	echo "Process with CRTOOLS_INIT_PID=$CRTOOLS_INIT_PID doesn't exist"
	exit 1
fi

NS_ENTER=/usr/nsenter
[ ! -x $NSENTER ] || NS_ENTER=/usr/bin/nsenter

if [ ! -x $NS_ENTER ]; then
	echo "$NS_ENTER binary not found"
	exit 2
fi

JOIN_CT="$NS_ENTER -t $CRTOOLS_INIT_PID -m -u -p"

# Skip container, if it's not systemd based
[ $($JOIN_CT basename -- $(readlink /proc/1/exe)) == "systemd" ] || exit 0

AUTOFS_SERVICES="proc-sys-fs-binfmt_misc.automount"

for service in $AUTOFS_SERVICES; do
	status=$($JOIN_CT systemctl is-active $service)
	if [ $status == "active" ]; then
		$JOIN_CT systemctl restart $service
		if [ $? -ne 0 ]; then
			echo "Failed to restart $service service"
			exit 2
		fi
		echo "$service restarted"
	else
		echo "$service skipped ($status)"
	fi
done

exit 0
