#!/bin/bash

ZP="zdtm/live"

TEST_LIST="
static/pipe00
static/pipe01
static/busyloop00
static/cwd00
static/env00
static/maps00
static/maps01
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
static/xids00
streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
static/sockets00
static/sockets_spair
static/sockets_dgram
static/socket_queues
static/pid00
static/pstree
static/caps00
static/cmdlinenv00
static/socket_listen
static/socket_udp
static/socket6_udp
static/socket_udplite
static/selfexe00
static/unlink_fstat00
static/unlink_fstat02
static/eventfs00
static/inotify00
static/unbound_sock
static/fifo-rowo-pair
static/fifo-ghost
static/fifo
static/fifo_wronly
"
# Duplicate list with pidns/ prefix
TEST_LIST=$TEST_LIST$(echo $TEST_LIST | tr ' ' '\n' | sed 's#^#pidns/#')

# These ones are not in pidns
TEST_LIST="$TEST_LIST
static/zombie00
transition/fork
static/file_fown
"

MNT_TEST_LIST="
static/mountpoints
"

# These ones are in pidns
TEST_LIST="$TEST_LIST
pidns/static/session00
"

UTS_TEST_LIST="
static/utsname
"

IPC_TEST_LIST="
static/ipc_namespace
static/shm
static/msgque
static/sem
transition/ipc
"

CRTOOLS=`pwd`/`dirname $0`/../crtools
TINIT=`pwd`/`dirname $0`/zdtm/lib/test_init
test -x $CRTOOLS || exit 1

ARGS=""

PID=""
PIDNS=""

start_test()
{
	local tdir=$1
	local tname=$2

	killall -9 $tname &> /dev/null
	make -C $tdir cleanout

	if [ -z "$PIDNS" ]; then
		make -C $tdir $tname.pid
		PID=`cat $test.pid` || return 1
	else
		killall -9 test_init
		$TINIT  $tdir $tname || {
			echo ERROR: fail to start $tdir/$tname
			return 1;
		}

		PID=`ps h -C test_init -o pid`
		PID=$((PID))
	fi
}

stop_test()
{
	local tdir=$1
	local tname=$2

	if [ -z "$PIDNS" ]; then
		make -C $tdir $tname.out
	else
		killall test_init
	fi
}

save_fds()
{
	test -n "$PIDNS" && return 0
	ls -l /proc/$1/fd | sed 's/\(-> \(pipe\|socket\)\):.*/\1/' | awk '{ print $9,$10,$11; }' > $2
}

diff_fds()
{
	test -n "$PIDNS" && return 0
	if ! diff -up $1 $2; then
		echo ERROR: Sets of descriptors are differ:
		echo $1
		echo $2
		return 1
	fi
}

run_test()
{
	local test=$1

	expr "$test" : 'pidns/' > /dev/null && PIDNS=1 || PIDNS=""
	test=${ZP}/${test#pidns/}

	shift
	local args=$*
	local tname=`basename $test`
	local tdir=`dirname $test`
	DUMP_PATH=""

	echo "Execute $test"

	start_test $tdir $tname || return 1

	local ddump
	kill -s 0 "$PID" || {
		echo "Get a wrong pid '$PID'"
		return 1
	}

	ddump=dump/$tname/$PID
	DUMP_PATH=`pwd`/$ddump

	if [ -n "$PIDNS" ]; then
		args="--namespace pid $args"
	fi

	echo Dump $PID
	mkdir -p $ddump
	save_fds $PID  $ddump/dump.fd
	setsid $CRTOOLS dump -D $ddump -o dump.log -v 4 -t $PID $args $ARGS || {
		echo WARNING: process $tname is left running for your debugging needs
		return 1
	}
	if expr " $ARGS" : ' -s' > /dev/null; then
		save_fds $pid  $ddump/dump.fd.after
		diff_fds $ddump/dump.fd $ddump/dump.fd.after || return 1
		killall -CONT $tname
	else
		while :; do
			killall -9 $tname &> /dev/null || break
			echo Waiting...
			sleep 0.1
		done

		echo Restore $PID
		setsid $CRTOOLS restore --log-pid -D $ddump -o restore.log -v 4 -d -t $PID $args || return 2

		save_fds $PID  $ddump/restore.fd
		diff_fds $ddump/dump.fd $ddump/restore.fd || return 2
	fi

	echo Check results $PID
	stop_test $tdir $tname
	sltime=1
	for i in `seq 50`; do
		test -f $test.out && break
		echo Waiting...
		sleep 0.$sltime
		[ $sltime -le 9 ] && ((sltime++))
	done
	cat $test.out
	cat $test.out | grep PASS || return 2
}

case_error()
{
	test=${ZP}/${1#pidns/}
	local test_log=`pwd`/$test.out

	echo "Test: $test"
	echo "====================== ERROR ======================"

	if [ -n "$DUMP_PATH" ]; then
		[ -e "$DUMP_PATH/dump.log" ] &&
			echo "Dump log   : $DUMP_PATH/dump.log"
		[ -e "$DUMP_PATH/restore.log" ] &&
			echo "Restore log: $DUMP_PATH/restore.log"
	fi
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
	for t in $MNT_TEST_LIST; do
		run_test $t -n mnt || case_error $t
	done
	for t in $IPC_TEST_LIST; do
		run_test $t -n ipc || case_error $t
	done
elif [ "$1" == "-l" ]; then
	echo $TEST_LIST $UTS_TEST_LIST $MNT_TEST_LIST $IPC_TEST_LIST | tr ' ' '\n'
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
	elif echo $MNT_TEST_LIST | fgrep -qw $1; then
		run_test $1 -n mnt || case_error $1
	elif echo $IPC_TEST_LIST | fgrep -qw $1; then
		run_test $1 -n ipc || case_error $1
	else
		run_test $1 || case_error $1
	fi
fi
