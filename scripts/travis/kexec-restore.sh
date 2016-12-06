#!/bin/bash

exec &>> /travis.log

DROPBOX_TOKEN=`cat /dropbox`
export DROPBOX_TOKEN

TRAVIS_BUILD_ID=`cat /travis_id`
export TRAVIS_BUILD_ID

set -x -m

sleep 15
cd $1

uname -a
lsmod
ps axf
ip a
ip r
iptables -L

touch /tmp/restore
./scripts/dropbox_upload.py /tmp/restore
./scripts/dropbox_upload.py /travis.log
dmesg > /dmesg.log
./scripts/dropbox_upload.py /dmesg.log

mkfifo $2
chmod 0600 $2
make -C test pidns
./test/pidns ./criu/criu restore -D /imgs -o restore.log -j --tcp-established --ext-unix-sk -v4 -l &
pid=$!
touch /rebooted
./scripts/dropbox_upload.py /rebooted
sleep 10
{
	ps axf
	dmesg > /dmesg.log
	./scripts/dropbox_upload.py /dmesg.log
	./scripts/dropbox_upload.py /travis.log
	./scripts/dropbox_upload.py /imgs/restore.log
}
while :; do
	sleep 1
	[ "`cat /proc/sys/kernel/tainted`" -ne "0" ] && {
		dmesg > /dmesg
		./scripts/dropbox_upload.py /dmesg
		break
	}
done
wait -n $pid
