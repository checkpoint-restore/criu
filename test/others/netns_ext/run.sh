#!/bin/bash

set -e

CRIU=../../../criu/criu
setsid unshare -n bash -c 'unshare -n sh _run.sh pidfile2 & unshare -n sh _run.sh pidfile3 & ip link add xxx type veth && ip link add mymacvlan1 link xxx type macvlan mode bridge && . _run.sh pidfile' < /dev/zero &> output &
sleep 1
while :; do
	test -f pidfile && test -f pidfile2 && break;
	sleep 0.1
done

pid=$(cat pidfile)
pid2=$(cat pidfile2)

touch test_netns
mount --bind /proc/$pid/ns/net test_netns
touch test_netns2
mount --bind /proc/$pid2/ns/net test_netns2
mkdir -p images
ino=$(ls -iL test_netns | awk '{ print $1 }')
ino2=$(ls -iL test_netns2 | awk '{ print $1 }')
exec 33< test_netns
exec 34< test_netns2
$CRIU dump -t $pid -o dump.log -D images --external net[$ino]:test_netns --external net[$ino2]:test_netns2
cat images/dump.log | grep -B 5 Error || echo ok
$CRIU restore -o restore.log -D images --inherit-fd fd[33]:test_netns --inherit-fd fd[34]:test_netns2 -d
cat images/restore.log | grep -B 5 Error || echo ok
new_ino=$(ls -iL /proc/$pid/ns/net | awk '{ print $1 }')
new_ino2=$(ls -iL /proc/$pid2/ns/net | awk '{ print $1 }')
[ "$ino" -ne "$new_ino" ] && {
	echo FAIL
	exit 1
}
[ "$ino2" -ne "$new_ino2" ] && {
	echo FAIL
	exit 1
}
echo PASS
exit 0
