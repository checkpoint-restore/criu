#!/bin/bash

ZP="zdtm/live"

TEST_LIST="
static/pipe00
static/busyloop00
static/cwd00
static/env00
static/maps00
static/mprotect00
static/mtime_mmap
static/sleeping00
static/write_read00
static/write_read01
static/write_read02
static/wait00
static/vdso00
static/file_shared
static/timers
static/futex
streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
transition/fork
static/zombie00
static/sockets00
static/pid00
static/pstree
static/caps00
static/cmdlinenv00
static/socket_listen
static/selfexe00
"

UTS_TEST_LIST="
static/utsname
"

IPC_TEST_LIST="
static/ipc_namespace
static/shm
static/msgque
static/sem
"

CRTOOLS=`pwd`/`dirname $0`/../crtools
test -x $CRTOOLS || exit 1
ARGS=""

run_test()
{
	local test=$ZP/$1
	shift
	local args=$*
	local tname=`basename $test`
	local tdir=`dirname $test`
	local ret

	killall -9 $tname
	make -C $tdir cleanout $tname.pid

	local pid ddump
	pid=`cat $test.pid` || return 1
	ddump=dump/$tname/$pid
	DUMP_PATH=`pwd`/$ddump

	echo Dump $pid
	mkdir -p $ddump
	setsid $CRTOOLS dump -D $ddump -o dump.log -t $pid $args $ARGS || return 1;

	if expr " $ARGS" : ' -s'; then
		killall -CONT $tname
	else
		while :; do
			killall -9 $tname &> /dev/null || break
			echo Waiting...
			sleep 1
		done

		echo Restore $pid
		setsid $CRTOOLS restore -D $ddump -o restore.log -d -t $pid $args || return 2
	fi

	echo Check results $pid
	make -C $tdir $tname.out
	for i in `seq 50`; do
		test -f $test.out && break
		echo Waiting...
		sleep 1
	done
	cat $test.out
	cat $test.out | grep PASS || return 2
}

case_error()
{
	local test=$ZP/$1
	local test_log=`pwd`/$test.out

	echo "Test: $test"
	echo "====================== ERROR ======================"

	[ -e "$DUMP_PATH/dump.log" ] &&
		echo "Dump log   : $DUMP_PATH/dump.log"
	[ -e "$DUMP_PATH/restore.log" ] &&
		echo "Restore log: $DUMP_PATH/restore.log"
	[ -e "$test_log" ] &&
		echo "Output file: $test_log"
	exit 1
}

cd `dirname $0` || exit 1

if [ "$1" == "-d" ]; then
	ARGS="-s"
	shift
fi

if [ $# -eq 0 ]; then
	for t in $TEST_LIST; do
		run_test $t || case_error $t
	done
	for t in $UTS_TEST_LIST; do
		run_test $t -n uts || case_error $t
	done
	for t in $IPC_TEST_LIST; do
		run_test $t -n ipc || case_error $t
	done
elif [ "$1" == "-l" ]; then
	echo $TEST_LIST $UTS_TEST_LIST $IPC_TEST_LIST | tr ' ' '\n'
elif [ "$1" == "-h" ]; then
	cat >&2 <<EOF
This script is used for executing unit tests.
Usage:
zdtm.sh [OPTIONS]
zdtm.sh [OPTIONS] [TEST NAME]
Options:
	-l : Show list of tests.
	-d : Dump a test process and check that this process can continue working.
EOF
else
	if echo $UTS_TEST_LIST | fgrep -qw $1; then
		run_test $1 -n uts || case_error $1
	elif echo $IPC_TEST_LIST | fgrep -qw $1; then
		run_test $1 -n ipc || case_error $1
	else
		run_test $1 || case_error $1
	fi
fi
