#!/bin/bash

ZP="zdtm/live"

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
	DUMP_PATH=`pwd`"/"$ddump

	echo Dump $pid
	mkdir -p $ddump
	setsid $CRTOOLS dump -D $ddump -o dump.log -t $pid $2 || return 1
	while :; do
		killall -9 $tname &> /dev/null || break;
		echo Waiting...
		sleep 1
	done

	echo Restore $pid
	setsid $CRTOOLS restore -D $ddump -o restore.log -d -t $pid $2 || return 2

	echo Check results $pid
	make -C $tdir $tname.out
	for i in `seq 50`; do
		test -f $test.out && break;
		echo Waiting...
		sleep 1
	done
	cat $test.out
	cat $test.out | grep PASS || return 2
}

case_error()
{
	test=$1
	test_log="`pwd`/$test.out"

	echo "Test: $test"
	echo "====================== ERROR ======================"

	[ -e "$DUMP_PATH/dump.log" ] && echo "Dump log   : $DUMP_PATH/dump.log"
	[ -e "$DUMP_PATH/restore.log" ] && echo "Restore log: $DUMP_PATH/restore.log"
	[ -e "$test_log" ] && echo "Output file: $test_log"
	exit 1
}

cd `dirname $0` || exit 1

if [ $# -eq 0 ]; then
	for t in $TEST_LIST; do
		run_test $t "" || case_error $t
	done
	for t in $UTS_TEST_LIST; do
		run_test $t "-n uts" || case_error $t
	done
	for t in $IPC_TEST_LIST; do
		run_test $t "-n ipc" || case_error $t
	done
elif [ "$1" == "-l" ]; then
	echo $TEST_LIST | sed -e "s#$ZP/##g" -e 's/ /\n/g'
	echo $UTS_TEST_LIST | sed -e "s#$ZP/##g" -e 's/ /\n/g'
	echo $IPC_TEST_LIST | sed -e "s#$ZP/##g" -e 's/ /\n/g'
else
	if echo "$UTS_TEST_LIST" | fgrep -q "$1" ; then
		run_test "$ZP/$1" "-n uts" || case_error "$ZP/$1"
	elif echo "$IPC_TEST_LIST" | fgrep -q "$1" ; then
		run_test "$ZP/$1" "-n ipc" || case_error "$ZP/$1"
	else
		run_test "$ZP/$1" || case_error "$ZP/$1"
	fi
fi
