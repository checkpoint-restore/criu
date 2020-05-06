#!/bin/bash

set -x

if [[ "$1" == "pid" ]]; then
	NS=pid
else
	NS=net
fi

MNT1=test_ns1
MNT2=test_ns2

trap "cleanup" QUIT TERM INT HUP EXIT

function cleanup()
{
	kill -9 $pid $pid2
	sleep 0.5
	umount -lf $MNT1 $MNT2 || :
	rm -f $MNT1 $MNT2
	rm -f pidfile pidfile2 pidfile3
}

CRIU=../../../criu/criu
if [[ "$NS" == "net" ]]; then
	setsid unshare -n bash -c 'unshare -n sh _run.sh pidfile2 & unshare -n sh _run.sh pidfile3 & ip link add xxx type veth && ip link add mymacvlan1 link xxx type macvlan mode bridge && . _run.sh pidfile' < /dev/zero &> output &
elif [[ "$NS" == "pid" ]]; then
	RND1=$RANDOM
	RND2=$RANDOM
	setsid unshare -p -f setsid bash -c "setsid sh _run.sh pidfile2 $RND2 & . _run.sh pidfile $RND1" < /dev/zero &> output &
fi
sleep 1
while :; do
	test -f pidfile && test -f pidfile2 && break;
	sleep 0.1
done

if [[ "$NS" == "net" ]]; then
	pid=$(cat pidfile)
	pid2=$(cat pidfile2)
elif [[ "$NS" == "pid" ]]; then
	pid2=$(pgrep -f ". _run.sh pidfile $RND1" -n)
	pid=$(pgrep -f "sh _run.sh pidfile2 $RND2" -n)
fi

touch $MNT1
mount --bind /proc/$pid/ns/$NS $MNT1
touch $MNT2
mount --bind /proc/$pid2/ns/$NS $MNT2
mkdir -p images
ino=$(ls -iL $MNT1 | awk '{ print $1 }')
ino2=$(ls -iL $MNT2 | awk '{ print $1 }')
exec 33< $MNT1
exec 34< $MNT2
$CRIU dump -v4 -t $pid -o dump.log -D images --external $NS[$ino]:test_ns --external $NS[$ino2]:test_ns2
cat images/dump.log | grep -B 5 Error || echo ok
$CRIU restore -v4 -o restore.log -D images --inherit-fd fd[33]:test_ns --inherit-fd fd[34]:test_ns2 -d
cat images/restore.log | grep -B 5 Error || echo ok
if [[ "$NS" == "pid" ]]; then
	pid=$(pgrep -f "^sh _run.sh pidfile2 $RND2")
fi
new_ino=$(ls -iL /proc/$pid/ns/$NS | awk '{ print $1 }')
new_ino2=$(ls -iL /proc/$pid2/ns/$NS | awk '{ print $1 }')
[ "$ino" != "$new_ino" ] && {
	echo FAIL
	exit 1
}
[ "$ino2" != "$new_ino2" ] && {
	echo FAIL
	exit 1
}
echo PASS
exit 0
