#!/usr/bin/env bash

# Check dump and restore of a cgroup namespace rooted at the cgroup CRIU is in,
# i.e. the one for which no cgns prefix is dumped.
#
# To get such a namespace, the test puts itself into a cgroup and unshares a
# cgroup namespace there, so that CRIU, started from here, sees all its cgroup
# paths as "/". The tasks to dump are then started in that very namespace root,
# with a cgroup namespace of their own, so no cgns prefix is dumped for them.
#
# The scenarios are:
#
#   shared  the task to dump is in the same cgroup as CRIU, so the dumped
#           cgroup set is CRIU's one, and a child task is in a nested cgroup.
#           As the cgroups of the two sets are an ancestor and its descendant,
#           they are expected to be dumped as a single tree.
#
#   ignore  same as above, but dumped and restored with --manage-cgroups=ignore,
#           where the namespace is the only thing to restore.
#
#   nested  the task to dump moves itself into a nested cgroup after unsharing
#           the namespace, so the dumped set is not CRIU's one, while the
#           namespace root is still the cgroup CRIU is in.

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source ../env.sh

CGNAME="criu-cgns-root"
MNT="$PWD/cgroup"
IMGDIR="$PWD/images"
# The hierarchy is mounted before the cgroup namespace is unshared, so it
# shows the cgroups as seen from the initial namespace even from inside the
# new one, i.e. the cgroup namespace root is $CGDIR rather than $MNT.
CGDIR="$MNT/test"

SCENARIOS=("shared" "ignore" "nested")

if [ -z "${CGNS_ROOT_INNER:-}" ]; then
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

	# shellcheck disable=SC2329 # invoked via trap
	cleanup() {
		# Move out of $CGDIR, otherwise it can't be removed, and the
		# leftover cgroup keeps the hierarchy alive after umount.
		echo $$ > "$MNT/cgroup.procs"
		rmdir "$CGDIR/child" "$CGDIR" || true
		umount "$MNT"
		rmdir "$MNT"
	}
	trap cleanup EXIT

	# The cgroup to unshare the namespace in, and the nested cgroup for the
	# child task. Both are created from here, as the hierarchy above the
	# root of the new cgroup namespace is not visible from inside it.
	mkdir -p "$CGDIR/child"
	echo $$ > "$CGDIR/cgroup.procs"

	# Run the rest in a cgroup namespace rooted at $CGDIR.
	unshare --cgroup env CGNS_ROOT_INNER=1 "$0" "$@"
	exit
fi

rootpid=""
childpid=""

fail() {
	echo "$*"
	kill_tasks
	echo FAIL
	exit 1
}

kill_tasks() {
	[ -n "$rootpid" ] && kill -9 "$rootpid" 2>/dev/null
	[ -n "$childpid" ] && kill -9 "$childpid" 2>/dev/null
	rootpid=""
	childpid=""
	return 0
}

cgns_of() {
	readlink "/proc/$1/ns/cgroup"
}

# The cgroup of a task in the hierarchy under test, as seen by the test.
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

# A session leader without a terminal, in a cgroup namespace of its own, with
# a child task in the nested cgroup.
start_with_child() {
	setsid --fork unshare --cgroup bash -c '
		exec </dev/null >/dev/null 2>&1
		bash -c "echo \$\$ > '"$CGDIR"'/child/cgroup.procs; echo \$\$ > '"$PWD"'/child.pid; exec sleep 10000" &
		echo $$ > '"$PWD"'/root.pid
		wait
	' &

	wait_for_pids root.pid child.pid || return 1
	rootpid=$(cat root.pid)
	childpid=$(cat child.pid)

	[ "$(cgroup_of "$childpid")" = "/child" ]
}

# Same, but the task moves itself into the nested cgroup once the namespace
# is unshared, and has no children.
start_in_nested() {
	setsid --fork unshare --cgroup bash -c '
		exec </dev/null >/dev/null 2>&1
		echo $$ > '"$CGDIR"'/child/cgroup.procs
		echo $$ > '"$PWD"'/root.pid
		exec sleep 10000
	' &

	wait_for_pids root.pid || return 1
	rootpid=$(cat root.pid)

	[ "$(cgroup_of "$rootpid")" = "/child" ]
}

dump_and_restore() {
	local mode="$1"

	# Otherwise the test checks nothing.
	[ "$(cgns_of "$rootpid")" != "$(cgns_of self)" ] ||
		fail "the task to dump shares the cgroup namespace with the test"

	"$criu" dump -D "$IMGDIR" -t "$rootpid" "--manage-cgroups=$mode" \
		-v4 --log-file dump.log || fail "dump failed"

	"$criu" restore -D "$IMGDIR" "--manage-cgroups=$mode" --restore-detached \
		-v4 --log-file restore.log || fail "restore failed"

	[ "$(cgns_of "$rootpid")" != "$(cgns_of self)" ] ||
		fail "the cgroup namespace is not restored"
}

# The cgroups of the dumped sets are "/" and "/child", so the controller is
# expected to have a single cgroup root (dumped with an empty name) with the
# nested cgroup as its child.
check_image() {
	$crit show "$IMGDIR/cgroup.img" > cgroup.json || fail "crit failed"
	python3 check-dirs.py "name=$CGNAME" cgroup.json ||
		fail "wrong cgroup tree in the image"
}

scenario_shared() {
	start_with_child || fail "can't start the tasks to dump"
	dump_and_restore soft

	local cgroup
	cgroup=$(cgroup_of "$childpid")
	[ "$cgroup" = "/child" ] ||
		fail "the child task is in $cgroup, expected /child"
}

scenario_ignore() {
	start_with_child || fail "can't start the tasks to dump"
	# In this mode CRIU does not move the restored tasks into any cgroup,
	# so the namespace, checked by dump_and_restore(), is all there is.
	dump_and_restore ignore
}

scenario_nested() {
	start_in_nested || fail "can't start the task to dump"
	dump_and_restore soft

	local cgroup
	cgroup=$(cgroup_of "$rootpid")
	[ "$cgroup" = "/child" ] ||
		fail "the task is in $cgroup, expected /child"

	# The namespace root has to be the cgroup CRIU is in, so the task sees
	# the very same path as the test does.
	cgroup=$(own_cgroup_of "$rootpid")
	[ "$cgroup" = "/child" ] ||
		fail "the task sees itself in $cgroup, expected /child"
}

if [ $# -gt 0 ]; then
	SCENARIOS=("$@")
fi

for scenario in "${SCENARIOS[@]}"; do
	echo "=== scenario: $scenario"
	rm -rf "$IMGDIR" ./*.pid
	mkdir -p "$IMGDIR"

	"scenario_$scenario"

	[ "$scenario" != "shared" ] || check_image
	kill_tasks
done

echo PASS
