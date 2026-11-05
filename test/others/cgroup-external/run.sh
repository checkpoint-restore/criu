#!/usr/bin/env bash

# Check that the cgroup CRIU is in is left alone on restore, even if some
# of the dumped tasks are in it, too. That cgroup is not owned by the dumped
# tasks: CRIU is there as well, and so is an unrelated nested cgroup. So
# neither the properties of the two cgroups are expected to be restored, nor
# the restore is expected to fail in the strict mode because the cgroup
# exists.
#
# The scenarios are:
#
#   cgns   the task to dump is in the same cgroup as CRIU, but in a cgroup
#          namespace of its own, so its cgroup set differs from the CRIU's
#          one by the cgns prefix, and is dumped.
#
#   above  the task to dump is in the same cgroup as CRIU, and its child is
#          in the parent cgroup, so the cgroup CRIU is in is found while
#          walking the cgroups of the child. As the child's cgroup exists
#          on restore, the strict mode is not checked here.

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source ../env.sh

CGNAME="criu-cg-external"
MNT="$PWD/cgroup"
IMGDIR="$PWD/images"
# The cgroup CRIU is in, and its parent.
CGDIR="$MNT/test/sub"
PARENT="$MNT/test"

SCENARIOS=("cgns" "above")

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: need to be root"
	exit 0
fi

if [ ! -e /proc/self/ns/cgroup ]; then
	echo "SKIP: no cgroup namespaces"
	exit 0
fi

mkdir -p "$MNT"
if ! mount -t cgroup -o "none,name=$CGNAME" none "$MNT"; then
	rmdir "$MNT"
	echo "SKIP: can't mount a named cgroup hierarchy"
	exit 0
fi

rootpid=""
childpid=""

kill_tasks() {
	local pid

	# The tasks are gone if the restore has failed.
	for pid in "$rootpid" "$childpid"; do
		if [ -n "$pid" ]; then
			kill -9 "$pid" 2>/dev/null || true
		fi
	done
	rootpid=""
	childpid=""
}

# shellcheck disable=SC2329 # invoked via trap
cleanup() {
	kill_tasks
	# Move out of $CGDIR, otherwise it can't be removed, and the
	# leftover cgroup keeps the hierarchy alive after umount.
	echo $$ > "$MNT/cgroup.procs"
	sleep 0.5
	rmdir "$CGDIR/other" "$CGDIR" "$PARENT" || true
	umount "$MNT"
	# The hierarchy is only destroyed on umount if it has no cgroups
	# but the root one, including the ones still being removed, and
	# until then it gets in the way of dumping any task, so mount and
	# umount it again until it is gone.
	for _ in $(seq 50); do
		grep -q ":name=$CGNAME:" /proc/self/cgroup || break
		if mount -t cgroup -o "none,name=$CGNAME" none "$MNT"; then
			umount "$MNT"
		fi
		sleep 0.1
	done
	rmdir "$MNT"
}
trap cleanup EXIT

fail() {
	echo "$*"
	echo FAIL
	exit 1
}

# The cgroup of a task in the hierarchy under test.
cgroup_of() {
	sed -n "s/.*:name=$CGNAME:\(.*\)/\1/p" "/proc/$1/cgroup"
}

# Same, but as seen from the cgroup namespace of the task itself.
own_cgroup_of() {
	nsenter --cgroup="/proc/$1/ns/cgroup" sed -n "s/.*:name=$CGNAME:\(.*\)/\1/p" "/proc/$1/cgroup"
}

wait_for_pids() {
	local _ pidfiles=("$@")

	for _ in $(seq 100); do
		# shellcheck disable=SC2015
		[ -s "${pidfiles[0]}" ] && [ -s "${pidfiles[-1]}" ] && return 0
		sleep 0.1
	done

	return 1
}

# A session leader without a terminal, in a cgroup namespace of its own.
start_cgns() {
	setsid --fork unshare --cgroup bash -c '
		exec </dev/null >/dev/null 2>&1
		echo $$ > '"$PWD"'/root.pid
		exec sleep 10000
	' &
	wait_for_pids root.pid || return 1
	rootpid=$(cat root.pid)
}

# A session leader without a terminal, with a child in the parent cgroup.
start_above() {
	setsid --fork bash -c '
		exec </dev/null >/dev/null 2>&1
		bash -c "echo \$\$ > '"$PARENT"'/cgroup.procs; echo \$\$ > '"$PWD"'/child.pid; exec sleep 10000" &
		echo $$ > '"$PWD"'/root.pid
		wait
	' &
	wait_for_pids root.pid child.pid || return 1
	rootpid=$(cat root.pid)
	childpid=$(cat child.pid)

	[ "$(cgroup_of "$childpid")" = "/test" ]
}

check_cgns() {
	[ "$(cgroup_of "$rootpid")" = "/test/sub" ] ||
		fail "the task is in $(cgroup_of "$rootpid"), expected /test/sub"
	[ "$(own_cgroup_of "$rootpid")" = "/" ] ||
		fail "the task sees itself in $(own_cgroup_of "$rootpid"), expected /"
}

check_above() {
	[ "$(cgroup_of "$rootpid")" = "/test/sub" ] ||
		fail "the task is in $(cgroup_of "$rootpid"), expected /test/sub"
	[ "$(cgroup_of "$childpid")" = "/test" ] ||
		fail "the child task is in $(cgroup_of "$childpid"), expected /test"
}

run() {
	local scenario="$1" mode="$2"

	echo "=== scenario: $scenario, mode: $mode"
	rm -rf "$IMGDIR" ./*.pid
	mkdir -p "$IMGDIR"
	echo 0 > "$CGDIR/notify_on_release"
	echo 0 > "$CGDIR/other/notify_on_release"

	"start_$scenario" || fail "can't start the tasks to dump"

	"$criu" dump -D "$IMGDIR" -t "$rootpid" "--manage-cgroups=$mode" \
		-v4 --log-file dump.log || fail "dump failed"

	# Change the properties of both cgroups after the dump.
	echo 1 > "$CGDIR/notify_on_release"
	echo 1 > "$CGDIR/other/notify_on_release"

	"$criu" restore -D "$IMGDIR" "--manage-cgroups=$mode" --restore-detached \
		-v4 --log-file restore.log || fail "restore failed"

	"check_$scenario"

	[ "$(cat "$CGDIR/notify_on_release")" = 1 ] ||
		fail "the properties of the cgroup CRIU is in are restored"
	[ "$(cat "$CGDIR/other/notify_on_release")" = 1 ] ||
		fail "the properties of an unrelated cgroup are restored"

	kill_tasks
}

# Both CRIU (started from here) and the task to dump are in $CGDIR.
mkdir -p "$CGDIR/other"
echo $$ > "$CGDIR/cgroup.procs"

if [ $# -gt 0 ]; then
	SCENARIOS=("$@")
fi

for scenario in "${SCENARIOS[@]}"; do
	run "$scenario" soft
	run "$scenario" full
	[ "$scenario" = "above" ] || run "$scenario" strict
done

echo PASS
