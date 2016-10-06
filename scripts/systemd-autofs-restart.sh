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

NS_ENTER=/bin/nsenter
[ ! -x $NSENTER ] || NS_ENTER=/usr/bin/nsenter

if [ ! -x $NS_ENTER ]; then
	echo "$NS_ENTER binary not found"
	exit 2
fi

JOIN_CT="$NS_ENTER -t $CRTOOLS_INIT_PID -m -u -p"

# Skip container, if it's not systemd based
[ "$($JOIN_CT basename -- $($JOIN_CT readlink /proc/1/exe))" == "systemd" ] || exit 0

AUTOFS_SERVICES="proc-sys-fs-binfmt_misc.automount"

bindmount=""

function remove_bindmount {
	if [ -n "$bindmount" ]; then
		$JOIN_CT umount $bindmount
		$JOIN_CT rm -rf $bindmount
		bindmount=""
	fi
}
trap remove_bindmount EXIT

function get_fs_type {
	local mountpoint=$1

	local top_mount_id=""
	local top_mount_fs_type=""

	while IFS='' read -r line; do
		# Skip those entries which do not match the mountpoint
		[ "$(echo $line | awk '{print $5;}')" = "$mountpoint" ] || continue

		local mnt_id=$(echo $line | awk '{print $1;}')
		local mnt_parent_id=$(echo $line | awk '{print $2;}')
		local mnt_fs_type=$(echo $line | sed 's/.* - //g' | awk '{print $1;}')

		# Skip mount entry, if not the first one and not a child
		[ -n "$top_mount_id" ] && [ "$mnt_parent_id" != "$top_mount_id" ] && continue

		top_mount_id=$mnt_id
		top_mount_fs_type=$mnt_fs_type
	done < "/proc/$CRTOOLS_INIT_PID/mountinfo"

	if [ -z "$top_mount_fs_type" ]; then
		echo "Failed to find $mountpoint mountpoint"
		return 1
	fi

	echo $top_mount_fs_type
	return 0
}

function bind_mount {
	local from=$1
	local to=$2

	$JOIN_CT mount --bind $from $to && return 0

	echo "Failed to bind mount $from to $to"
	return 1
}

function save_mountpoint {
	local mountpoint=$1
	local top_mount_fs_type=""

	top_mount_fs_type=$(get_fs_type $mountpoint)
	if [ $? -ne 0 ]; then
		echo "$top_mount_fs_type"
		return
	fi

	# Nothing to do, if no file system is on top of autofs
	[ "$top_mount_fs_type" = "autofs" ] && return

	bindmount=$($JOIN_CT mktemp -d)
	if [ -z "$bindmount" ]; then
		echo "Failed to create temporary directory"
		return 1
	fi

	# No need to unmount fs on top of autofs:
	# systemd will does it for us on service restart
	bind_mount $mountpoint $bindmount || $JOIN_CT rm -rf $bindmount
}

function restore_mountpoint {
	local mountpoint=$1

	[ -n "$bindmount" ] || return

	# Umount file system, remounted by systemd, if any
	if ! check_fs_type $mountpoint "autofs"; then
		$JOIN_CT umount $mountpoint || echo "Failed to umount $mountpoint"
	fi

	# Restore origin file system even if we failed to unmount the new one
	bind_mount $bindmount $mountpoint
	remove_bindmount
}

function restart_service {
	local service=$1
	local mountpoint=$($JOIN_CT systemctl show $service -p Where | sed 's/.*=//g')

	if [ -z "$mountpoint" ]; then
		echo "Failed to discover $service mountpoint"
		return
	fi

	# Try to move restored bind-mount aside and exit if Failed
	# Nothing to do, if we Failed
	save_mountpoint $mountpoint || return

	$JOIN_CT systemctl restart $service
	if [ $? -ne 0 ]; then
		echo "Failed to restart $service service"
		return
	fi
	echo "$service restarted"

	# Try to move saved monutpoint back on top of autofs
	restore_mountpoint $mountpoint
}

for service in $AUTOFS_SERVICES; do
	status=$($JOIN_CT systemctl is-active $service)

	if [ $status == "active" ]; then
		restart_service $service
	else
		echo "$service skipped ($status)"
	fi
done

exit 0
