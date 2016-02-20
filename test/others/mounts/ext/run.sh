#!/bin/bash

set -x

function fail {
	echo $@
	exit 1
}

make || fail "Can't compile library or ns init"

criu="../../../criu/criu"

# New root for namespace
NSROOT="nsroot"
# External file with contents (exported for plugin.restore)
EMP_ROOT="external_file"
export EMP_ROOT_P="$(pwd)/$EMP_ROOT"
# Internal file as seen from namespace (exported for plugin.dump)
export EMP_MOUNTPOINT="file"
# Message in a file to check visibility
FMESSAGE="tram-pam-pam"
# Binary of namespace's init
NS_INIT="ns_init"
# File with namespace init pid
PIDF="pidf"

start_ns()
{
	#
	# Prepare the namespace's FS layout
	#
	mkdir $NSROOT
	echo -n "$FMESSAGE" > "$EMP_ROOT"
	mount --bind "$NSROOT" "$NSROOT"
	mount --make-private "$NSROOT"
	touch "$NSROOT/$EMP_MOUNTPOINT"
	mount --bind "$EMP_ROOT" "$NSROOT/$EMP_MOUNTPOINT" || fail "Can't prepare fs for ns"

	#
	# Start the namespace's init
	#
	cp $NS_INIT "$NSROOT/"
	"./$NSROOT/$NS_INIT" "$PIDF" "$NSROOT" "log" "$EMP_MOUNTPOINT" "$FMESSAGE" || fail "Can't start namespace"
	umount "$NSROOT/$EMP_MOUNTPOINT"

	echo "Namespace started, pid $(cat $PIDF)"
}

stop_ns()
{
	#
	# Kill the init
	#

	kill -TERM $(cat $PIDF)
	sleep 2 # Shitty, but...
	umount $NSROOT

	if [ -z "$1" ]; then
		rm -f "$NSROOT/log"
	else
		mv "$NSROOT/log" "$1"
	fi

	rm -f "$PIDF" "$EMP_ROOT" "$NSROOT/$NS_INIT" "$NSROOT/log" "$NSROOT/$EMP_MOUNTPOINT"
	rmdir "$NSROOT/oldm"
	rmdir "$NSROOT/proc"
	rmdir "$NSROOT"
}

DDIR="dump"
rm -rf $DDIR
mkdir $DDIR

chk_pass()
{
	tail -n1 $1 | fgrep -q "PASS"
}

#
# Test 1: handle external mount with plugin
#

test_plugin()
{
	echo "=== Testing how plugin works"
	mkdir "$DDIR/plugin/"
	start_ns

	$criu dump    -D "$DDIR/plugin/" -v4 -o "dump.log" --lib=$(pwd) \
			-t $(cat pidf) || { stop_ns; return 1; }

	$criu restore -D "$DDIR/plugin/" -v4 -o "rstr.log" --lib=$(pwd) \
			-d --root="$(pwd)/$NSROOT" --pidfile=$PIDF || { stop_ns; return 1; }

	echo "Restored, checking results"
	mv "$DDIR/plugin/$PIDF" .
	stop_ns "$DDIR/plugin/ns.log"
	chk_pass "$DDIR/plugin/ns.log"
}

test_ext_mount_map()
{
	echo "=== Testing how --ext-mount-map works"
	mkdir "$DDIR/ext_mount_map/"
	start_ns

	$criu dump    -D "$DDIR/ext_mount_map/" -v4 -o "dump.log" \
			-t $(cat pidf) --ext-mount-map "/$EMP_MOUNTPOINT:TM" || { stop_ns; return 1; }

	$criu restore -D "$DDIR/ext_mount_map/" -v4 -o "rstr.log" \
			-d --root="$(pwd)/$NSROOT" --pidfile=$PIDF --ext-mount-map "TM:$EMP_ROOT_P" || { stop_ns; return 1; }

	echo "Restored, checking results"
	mv "$DDIR/ext_mount_map/$PIDF" .
	stop_ns "$DDIR/ext_mount_map/ns.log"
	chk_pass "$DDIR/ext_mount_map/ns.log"
}

test_plugin || exit 1
test_ext_mount_map || exit 1

echo "All tests passed"
exit 0
