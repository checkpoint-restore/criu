#!/bin/bash

ZP="zdtm/live/"

TEST_LIST="\
$ZP/static/pipe00
$ZP/static/busyloop00
$ZP/static/cwd00
$ZP/static/env00
$ZP/static/shm
$ZP/static/maps00
$ZP/static/mprotect00
$ZP/static/mtime_mmap
$ZP/static/sleeping00
$ZP/static/write_read00
$ZP/static/write_read01
$ZP/static/write_read02
$ZP/static/wait00
$ZP/static/vdso00
$ZP/static/file_shared
$ZP/static/timers
$ZP/streaming/pipe_loop00
$ZP/streaming/pipe_shared00
$ZP/transition/file_read
$ZP/transition/fork
$ZP/static/zombie00
$ZP/static/sockets00
$ZP/static/pid00
$ZP/static/caps00
$ZP/static/cmdlinenv00
$ZP/static/socket_listen"

UTS_TEST_LIST="\
$ZP/static/utsname"
IPC_TEST_LIST="\
$ZP/static/ipc_namespace"

CRTOOLS=`pwd`/`dirname $0`/../crtools

run_test()
{
	test=$1
	tname=`basename $test`
	tdir=`dirname $test`

	killall -9 $tname
	make -C $tdir cleanout $tname.pid
	pid=`cat $test.pid`
	ddump="dump/$tname/$pid"
	dump_path=`pwd`"/"$ddump
	mkdir -p $ddump
	ls -l /proc/$pid/fd/
	setsid $CRTOOLS dump -D $ddump -o dump.log -t $pid $2 || return 1
	while :; do
		killall -9 $tname &> /dev/null || break;
		echo Waiting...
		sleep 1
	done
	setsid $CRTOOLS restore -D $ddump -o restore.log -d -t $pid $2 || return 2
	ls -l /proc/$pid/fd/
	make -C $tdir $tname.out
	for i in `seq 50`; do
		test -f $test.out && break;
		echo Waiting...
		sleep 1
	done
	cat $test.out
	cat $test.out | grep PASS || return 2
}

cd `dirname $0` || exit 1

if [ $# -eq 0 ]; then
	for t in $TEST_LIST; do
		run_test $t "" || exit 1
	done
	for t in $UTS_TEST_LIST; do
		run_test $t "-n uts" || exit 1
	done
	for t in $IPC_TEST_LIST; do
		run_test $t "-n ipc" || exit 1
	done
elif [ "$1" == "-l" ]; then
	echo $TEST_LIST | sed -e "s#$ZP/##g" -e 's/ /\n/g'
	echo $UTS_TEST_LIST | sed -e "s#$ZP/##g" -e 's/ /\n/g'
else
	if echo "$UTS_TEST_LIST" | fgrep -q "$1" ; then
		run_test "$ZP/$1" "-n uts" && exit 0
	elif echo "$IPC_TEST_LIST" | fgrep -q "$1" ; then
		run_test "$ZP/$1" "-n ipc" && exit 0
	else
		run_test "$ZP/$1" && exit 0
	fi
	result=$?
	echo "====================== ERROR ======================"
	if [ $result == 1 ]; then
		echo "Dump log: "$dump_path"/dump.log"
	else
		echo "Restore log: "$dump_path"/restore.log"
	fi
fi
