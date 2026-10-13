#!/bin/bash
#
# Restore of tasks living in a user namespace which shares criu's mount
# namespace (issue #2597):
#
#   - just a new user namespace;
#   - new user and pid namespaces.
#
# In both cases a fresh procfs instance is (or is not) required and may
# (or may not) be mountable from the restored task itself, see the
# comment near mount_proc() in criu/cr-restore.c.

set -ex

CRIU=$(readlink -f "${CRIU:-../../../criu/criu}")
WORKDIR=$(mktemp -d /tmp/criu-userns-XXXXXX)
PROG=$WORKDIR/userns-prog

cleanup()
{
	cd /
	[ -n "$RPID" ] && kill -9 "$RPID" 2>/dev/null
	pkill -9 -x userns-prog 2>/dev/null
	rm -rf "$WORKDIR"
}
trap 'cleanup || :' QUIT TERM INT HUP EXIT

fail()
{
	echo "FAIL: $*"
	for log in "$WORKDIR"/*.log; do
		[ -e "$log" ] && tail -20 "$log"
	done
	exit 1
}

skip()
{
	echo "SKIP: $*"
	exit 0
}

[ "$(id -u)" = 0 ] || skip "must be run as root"
unshare --user --map-root-user true 2>/dev/null || skip "CLONE_NEWUSER is not supported"
# Set FORCE=1 to run the test even if criu does not believe it can
# restore user namespaces.
if [ -z "$FORCE" ]; then
	"$CRIU" check --feature userns >/dev/null 2>&1 || \
		skip "criu does not support restoring user namespaces"
fi

gcc -Wall -o "$PROG" "$(dirname "$0")/userns-prog.c"

HOST_USER_NS=$(readlink /proc/self/ns/user)
HOST_MNT_NS=$(readlink /proc/self/ns/mnt)
HOST_PID_NS=$(readlink /proc/self/ns/pid)

count_runs()
{
	awk '/^Running/ {n++} END {print n+0}' "$WORKDIR/prog.out"
}

# dump_restore [unshare options]
#
# Start the workload in a fresh user namespace sharing criu's mount (and,
# unless --pid is passed, pid) namespace, checkpoint it, restore it and
# leave the restored task running in $RPID. The workload re-opens its
# output file on restore and its counter must keep growing.
dump_restore()
{
	RPID=
	pkill -9 -x userns-prog 2>/dev/null || :
	rm -rf "$WORKDIR/img" "$WORKDIR/restored.pid"
	mkdir "$WORKDIR/img"
	: > "$WORKDIR/prog.out"

	cd "$WORKDIR"
	# The workload must not share its stdout with the unshare wrapper:
	# the wrapper may write to it after the checkpoint, which would
	# break size based file validation on restore.
	unshare --user --map-root-user "$@" -- \
		"$PROG" </dev/null >"$WORKDIR/prog.out" 2>/dev/null &
	local i pid
	pid=
	for i in $(seq 50); do
		pid=$(pgrep -nx userns-prog) && break
		sleep 0.2
	done
	[ -n "$pid" ] || fail "the workload did not start"

	"$CRIU" dump -t "$pid" -D "$WORKDIR/img" -j -v4 \
		-o "$WORKDIR/dump.log" || fail "criu dump failed"

	"$CRIU" restore -D "$WORKDIR/img" -j -v4 \
		-o "$WORKDIR/restore.log" \
		--restore-detached --pidfile "$WORKDIR/restored.pid" || \
		fail "criu restore failed"
	RPID=$(cat "$WORKDIR/restored.pid")
	[ -d /proc/$RPID ] || fail "the restored task is not running"

	# The counter must keep growing across checkpoint/restore.
	local before after
	before=$(count_runs)
	sleep 2
	after=$(count_runs)
	[ "$after" -gt "$before" ] || fail "the restored task is stuck"
	cd /
}

# check_ns <pid> <same|new>
#
# The task must have a fresh user namespace and share the mount one with
# criu. Its pid namespace must be shared ("same") or fresh ("new").
check_ns()
{
	local pid=$1 expect=$2
	local user_ns mnt_ns pid_ns
	user_ns=$(readlink /proc/$pid/ns/user)
	mnt_ns=$(readlink /proc/$pid/ns/mnt)
	pid_ns=$(readlink /proc/$pid/ns/pid)
	echo "ns of $pid: user=$user_ns mnt=$mnt_ns pid=$pid_ns"
	[ "$user_ns" != "$HOST_USER_NS" ] || fail "user namespace was not restored"
	[ "$mnt_ns" = "$HOST_MNT_NS" ] || fail "mount namespace must be shared"
	if [ "$expect" = same ]; then
		[ "$pid_ns" = "$HOST_PID_NS" ] || fail "pid namespace must be shared"
	else
		[ "$pid_ns" != "$HOST_PID_NS" ] || fail "pid namespace was not restored"
		# The restored task is the init task of its pid namespace.
		[ "$(awk '/^NSpid:/ {print $NF}' /proc/$pid/status)" = 1 ] || \
			fail "the restored task must be init of its pid namespace"
	fi
}

echo "=== a new user namespace, shared mount and pid namespaces ==="
dump_restore
check_ns "$RPID" same
kill -9 "$RPID" 2>/dev/null || :
RPID=
wait 2>/dev/null || :

echo "=== new user and pid namespaces, shared mount namespace ==="
dump_restore --pid --fork
check_ns "$RPID" new

echo "PASS"
