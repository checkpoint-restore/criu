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
#   cgroot  same as shared, but restored with --cgroup-root, so both tasks,
#           as well as the namespace root, are expected to be moved under the
#           new root.
#
#   moved   same as shared, but restored from another cgroup, so the task
#           which was in the CRIU's cgroup on dump is expected to be put back
#           there, i.e. into the namespace root, rather than to stay in the
#           cgroup CRIU is in on restore.
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

SCENARIOS=("shared" "cgroot" "moved" "ignore" "nested")

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
		rmdir "$CGDIR/new/child" "$CGDIR/new" "$CGDIR/child" "$CGDIR/elsewhere" "$CGDIR" || true
		umount "$MNT"
		# The hierarchy is only destroyed on umount if it has no
		# cgroups but the root one, including the ones still being
		# removed, and until then it gets in the way of dumping any
		# task, so mount and umount it again until it is gone.
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

	# The cgroup to unshare the namespace in, and the nested cgroup for the
	# child task. Both are created from here, as the hierarchy above the
	# root of the new cgroup namespace is not visible from inside it.
	mkdir -p "$CGDIR/child" "$CGDIR/elsewhere"
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

# The cgroup to run the restore from, if not the one CRIU was in on dump.
RESTORE_CGROUP=""

dump_and_restore() {
	local mode="$1"
	shift

	# Otherwise the test checks nothing.
	[ "$(cgns_of "$rootpid")" != "$(cgns_of self)" ] ||
		fail "the task to dump shares the cgroup namespace with the test"

	"$criu" dump -D "$IMGDIR" -t "$rootpid" "--manage-cgroups=$mode" \
		-v4 --log-file dump.log || fail "dump failed"

	[ -z "$RESTORE_CGROUP" ] || echo $$ > "$CGDIR/$RESTORE_CGROUP/cgroup.procs"
	"$criu" restore -D "$IMGDIR" "--manage-cgroups=$mode" --restore-detached "$@" \
		-v4 --log-file restore.log || fail "restore failed"
	[ -z "$RESTORE_CGROUP" ] || echo $$ > "$CGDIR/cgroup.procs"

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

# Check that the tasks started by start_with_child() are back in their
# cgroups, as seen both by the test and by the tasks themselves.
check_with_child() {
	local cgroup

	cgroup=$(cgroup_of "$rootpid")
	[ "$cgroup" = "/" ] ||
		fail "the task is in $cgroup, expected /"
	cgroup=$(cgroup_of "$childpid")
	[ "$cgroup" = "/child" ] ||
		fail "the child task is in $cgroup, expected /child"

	cgroup=$(own_cgroup_of "$rootpid")
	[ "$cgroup" = "/" ] ||
		fail "the task sees itself in $cgroup, expected /"
	cgroup=$(own_cgroup_of "$childpid")
	[ "$cgroup" = "/child" ] ||
		fail "the child task sees itself in $cgroup, expected /child"
}

scenario_shared() {
	start_with_child || fail "can't start the tasks to dump"
	dump_and_restore soft
	check_with_child
}

scenario_moved() {
	start_with_child || fail "can't start the tasks to dump"
	RESTORE_CGROUP=elsewhere dump_and_restore soft
	check_with_child
}

scenario_cgroot() {
	start_with_child || fail "can't start the tasks to dump"
	dump_and_restore soft --cgroup-root /new

	local cgroup
	cgroup=$(cgroup_of "$rootpid")
	[ "$cgroup" = "/new" ] ||
		fail "the task is in $cgroup, expected /new"
	cgroup=$(cgroup_of "$childpid")
	[ "$cgroup" = "/new/child" ] ||
		fail "the child task is in $cgroup, expected /new/child"

	# The namespace root is expected to be moved to the new root as well.
	cgroup=$(own_cgroup_of "$rootpid")
	[ "$cgroup" = "/" ] ||
		fail "the task sees itself in $cgroup, expected /"
	cgroup=$(own_cgroup_of "$childpid")
	[ "$cgroup" = "/child" ] ||
		fail "the child task sees itself in $cgroup, expected /child"
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
