#!/bin/bash

set -e

# CentOS 7 kernels do not have NSpid -> skip this test
grep NSpid /proc/self/status || exit 0

# This test creates a process in non-host pidns and then dumps it and restores
# it into host pidns. We use pid >100000 in non-host pidns to make sure it does
# not intersect with some host pid on restore but it is potentially racy so
# please run this test only in manualy.

CRIU=../../../criu/criu

# This is a status pipe to report the pid of __run_pidns.sh
exec {pipe}<> <(:)
exec {pipe_r}</proc/self/fd/$pipe
exec {pipe_w}>/proc/self/fd/$pipe
exec {pipe}>&-

unshare -p sh -c "bash _run_pidns.sh $pipe_w &"
exec {pipe_w}>&-

PID=$(cat <&$pipe_r)
echo PID: $PID

PIDNS=$(readlink /proc/$PID/ns/pid | sed 's/://')
echo PIDNS: $PIDNS

BEFORE=$(grep NSpid /proc/$PID/status)
echo "before c/r: $BEFORE"

rm -rf images_pidns || :
mkdir -p images_pidns

echo "$CRIU dump -v4 -o dump.log -t $PID -D images_pidns --external $PIDNS:exti"
$CRIU dump -v4 -o dump.log -t $PID -D images_pidns --external $PIDNS:exti
RESULT=$?
cat images_pidns/dump.log | grep -B 5 Error || echo ok
[ "$RESULT" != "0" ] && {
	echo "CRIU dump failed"
	echo FAIL
	exit 1
}

exec {pidns_fd}< /proc/self/ns/pid

echo "$CRIU restore -v4 -o restore.log -D images_pidns --restore-detached --inherit-fd fd[$pidns_fd]:exti"
$CRIU restore -v4 -o restore.log -D images_pidns --restore-detached --inherit-fd fd[$pidns_fd]:exti --pidfile test.pidfile
RESULT=$?
cat images_pidns/restore.log | grep -B 5 Error || echo ok
[ "$RESULT" != "0" ] && {
	echo "CRIU restore failed"
	echo FAIL
	exit 1
}

PID=$(cat images_pidns/test.pidfile)
AFTER=$(grep NSpid /proc/$PID/status)
echo "after c/r: $AFTER"
echo PASS
exit 0
