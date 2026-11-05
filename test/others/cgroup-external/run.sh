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
#
#   below  the task to dump is as in cgns, and its children are in the
#          cgroups below the one CRIU is in: a/b, then a (so that a/b is
#          collected before a), and x/y (so that x, with no task in it, is
#          in between the cgroup CRIU is in and the one of a task). The
#          cgroups of the children are removed before restore, except
#          for x, which is not owned by the dumped tasks, so it is not
#          expected to be restored.

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

SCENARIOS=("cgns" "above" "below")
# The cgroups of the children in the below scenario, in the order they
# are created in, relative to $CGDIR.
BELOW_CGROUPS=("a/b" "a" "x/y")

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
childpids=()

kill_tasks() {
	local pid

	# The tasks are gone if the restore has failed.
	for pid in "$rootpid" "${childpids[@]}"; do
		if [ -n "$pid" ]; then
			kill -9 "$pid" 2>/dev/null || true
		fi
	done
	rootpid=""
	childpids=()
}

# shellcheck disable=SC2329 # invoked via trap
cleanup() {
	kill_tasks
	# Move out of $CGDIR, otherwise it can't be removed, and the
	# leftover cgroup keeps the hierarchy alive after umount.
	echo $$ > "$MNT/cgroup.procs"
	sleep 0.5
	rmdir "$CGDIR/a/b" "$CGDIR/a" "$CGDIR/x/y" "$CGDIR/x" \
		"$CGDIR/other" "$CGDIR" "$PARENT" || true
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
	childpids=("$(cat child.pid)")

	[ "$(cgroup_of "${childpids[0]}")" = "/test" ]
}

# Same as cgns, with the children in the cgroups below.
start_below() {
	local i pidfiles=()

	for i in "${!BELOW_CGROUPS[@]}"; do
		mkdir -p "$CGDIR/${BELOW_CGROUPS[$i]}"
		pidfiles+=("child.$i.pid")
	done
	echo 0 > "$CGDIR/x/notify_on_release"

	setsid --fork unshare --cgroup bash -c '
		exec </dev/null >/dev/null 2>&1
		i=0
		for cg in '"${BELOW_CGROUPS[*]}"'; do
			bash -c "echo \$\$ > '"$CGDIR"'/$cg/cgroup.procs; echo \$\$ > '"$PWD"'/child.$i.pid; exec sleep 10000" &
			while [ ! -s '"$PWD"'/child.$i.pid ]; do sleep 0.1; done
			i=$((i + 1))
		done
		echo $$ > '"$PWD"'/root.pid
		wait
	' &
	wait_for_pids root.pid "${pidfiles[@]}" || return 1
	rootpid=$(cat root.pid)
	for i in "${!pidfiles[@]}"; do
		childpids+=("$(cat "${pidfiles[$i]}")")
	done
}

# The cgroups of the children are owned by the dumped tasks, so remove
# them, for the strict mode not to fail. Leave x, which is not.
after_dump_below() {
	rmdir "$CGDIR/a/b" "$CGDIR/a" "$CGDIR/x/y"
	echo 1 > "$CGDIR/x/notify_on_release"
}

# The cgroups in the image, one per line, as "path external".
image_cgroups() {
	$crit decode -i "$IMGDIR/cgroup.img" | python3 -c '
import json, sys

def walk(dirs, parent):
    for d in dirs:
        path = parent + "/" + d["dir_name"]
        print(path, d.get("external", False))
        walk(d.get("children", []), path)

for c in json.load(sys.stdin)["entries"][0]["controllers"]:
    if "name='"$CGNAME"'" in c["cnames"]:
        walk(c.get("dirs", []), "")
'
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
	[ "$(cgroup_of "${childpids[0]}")" = "/test" ] ||
		fail "the child task is in $(cgroup_of "${childpids[0]}"), expected /test"
}

check_below() {
	local i cg expected

	check_cgns
	for i in "${!BELOW_CGROUPS[@]}"; do
		cg=$(cgroup_of "${childpids[$i]}")
		[ "$cg" = "/test/sub/${BELOW_CGROUPS[$i]}" ] ||
			fail "child $i is in $cg, expected /test/sub/${BELOW_CGROUPS[$i]}"
	done

	# Each cgroup is below its parent, and the ones not owned by the
	# dumped tasks are external.
	expected="/test/sub True
/test/sub/a False
/test/sub/a/b False
/test/sub/x True
/test/sub/x/y False"
	[ "$(image_cgroups)" = "$expected" ] ||
		fail "unexpected cgroups in the image: $(image_cgroups)"

	[ "$(cat "$CGDIR/x/notify_on_release")" = 1 ] ||
		fail "the properties of an external cgroup in between are restored"
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

	if declare -F "after_dump_$scenario" >/dev/null; then
		"after_dump_$scenario"
	fi

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
