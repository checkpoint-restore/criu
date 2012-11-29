#!/bin/sh

ZP="zdtm/live"

TEST_LIST="
static/pipe00
static/pipe01
static/busyloop00
static/cwd00
static/env00
static/maps00
static/maps01
static/maps02
static/mprotect00
static/mtime_mmap
static/sleeping00
static/write_read00
static/write_read01
static/write_read02
static/write_read10
static/wait00
static/vdso00
static/sched_prio00
static/sched_policy00
static/file_shared
static/timers
static/futex
static/futex-rl
static/xids00
static/groups
static/pthread00
static/pthread01
streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
static/sockets00
static/sockets01
static/sock_opts00
static/sock_opts01
static/sockets_spair
static/sockets_dgram
static/socket_queues
static/sk-unix-unconn
static/pid00
static/pstree
static/caps00
static/cmdlinenv00
static/socket_listen
static/socket_listen6
static/packet_sock
static/socket_udp
static/sock_filter
static/socket6_udp
static/socket_udplite
static/selfexe00
static/unlink_fstat00
static/unlink_fstat02
static/unlink_fstat03
static/eventfs00
static/signalfd00
static/inotify00
static/unbound_sock
static/fifo-rowo-pair
static/fifo-ghost
static/fifo
static/fifo_wronly
static/zombie00
transition/fork
static/pty00
static/pty01
static/pty04
static/tty02
static/child_opened_proc
static/cow01
"
# Duplicate list with ns/ prefix
TEST_LIST=$TEST_LIST$(echo $TEST_LIST | tr ' ' '\n' | sed 's#^#ns/#')

# These ones are not in ns
TEST_LIST="$TEST_LIST
static/file_fown
static/socket-ext
static/socket-tcp
static/socket-tcp6
streaming/socket-tcp
streaming/socket-tcp6
static/socket-tcpbuf
static/socket-tcpbuf6
static/pty03
"

MNT_TEST_LIST="
static/mountpoints
"

# These ones are in ns
TEST_LIST="$TEST_LIST
ns/static/session00
ns/static/session01
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

TEST_CR_KERNEL="
static/sock_opts01
static/sockets01
static/sock_filter
static/socket-tcp6
streaming/socket-tcp6
static/socket-tcpbuf6
static/eventfs00
static/signalfd00
static/inotify00
$IPC_TEST_LIST
"

CRTOOLS=`pwd`/`dirname $0`/../crtools
TINIT=`pwd`/`dirname $0`/zdtm/lib/test_init
test -x $CRTOOLS || exit 1

ARGS=""

PID=""
PIDNS=""

ITERATIONS=1

check_mainstream()
{
	local -a ver_arr
	local ver_str=`uname -r`

	$CRTOOLS check && return 0
	MAINSTREAM_KERNEL=1

	cat >&2 <<EOF
============================= WARNING =============================
Not all C/R features are commited in the meainstream kernel.
Linux C/R can be cloned from:
git://git.kernel.org/pub/scm/linux/kernel/git/gorcunov/linux-cr.git
===================================================================
EOF

	ver_arr=(`echo ${ver_str//./ }`)

	[ "${ver_arr[0]}" -gt 3 ] && return 0
	[[ "${ver_arr[0]}" -eq 3 && "${ver_arr[1]}" -ge 7 ]] && return 0

	echo "A version of kernel should be greater or equal to 3.7"

	return 1;
}

umount_zdtm_root()
{
	[ -z "$ZDTM_ROOT" ] && return;
	umount -l "$ZDTM_ROOT"
	rmdir "$ZDTM_ROOT"
}
trap umount_zdtm_root EXIT

construct_root()
{
	local root=$1
	local test_path=$2
	local libdir=$root/lib64

	mkdir $libdir
	for i in `ldd $test_path | awk '{ print $1 }' | grep -v vdso`; do
		local lib=`basename $i`
		[ -f $libdir/$lib ] && continue ||
		[ -f $i ] && cp $i $libdir && continue ||
		[ -f /lib64/$i ] && cp /lib64/$i $libdir && continue ||
		[ -f /usr/lib64/$i ] && cp /usr/lib64/$i $libdir || return 1
	done
}

start_test()
{
	local tdir=$1
	local tname=$2
	export ZDTM_ROOT
	TPID=`readlink -f $tdir`/$tname.init.pid

	killall -9 $tname > /dev/null 2>&1
	make -C $tdir cleanout

	if [ -z "$PIDNS" ]; then
		make -C $tdir $tname.pid
		PID=`cat $test.pid` || return 1
	else
		if [ -z "$ZDTM_ROOT" ]; then
			mkdir dump
			ZDTM_ROOT=`mktemp -d dump/crtools-root.XXXXXX`
			ZDTM_ROOT=`readlink -f $ZDTM_ROOT`
			mount --bind . $ZDTM_ROOT || return 1
		fi
		construct_root $ZDTM_ROOT $tdir/$tname || return 1
	(	export ZDTM_NEWNS=1
		export ZDTM_PIDFILE=$TPID
		cd $ZDTM_ROOT
		rm -f $ZDTM_PIDFILE
		make -C $tdir $tname.pid || {
			echo ERROR: fail to start $tdir/$tname
			return 1;
		}
	)

		PID=`cat "$TPID"`
		ps -p $PID || return 1
	fi
}

stop_test()
{
	local tdir=$1
	local tname=$2

	if [ -z "$PIDNS" ]; then
		make -C $tdir $tname.out
	else
		kill `cat "$TPID"`
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

	[ -n "$MAINSTREAM_KERNEL" ] && echo $TEST_CR_KERNEL | grep -q ${test#ns/} && {
		echo "Skip $test"
		return 0
	}

	expr "$test" : 'ns/' > /dev/null && PIDNS=1 || PIDNS=""
	test=${ZP}/${test#ns/}

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

	if [ -n "$PIDNS" ]; then
		[ -z "$CR_IP_TOOL" ] && CR_IP_TOOL=ip
		$CR_IP_TOOL a help 2>&1 | grep -q showdump || {
			cat >&2 <<EOF
The util "ip" is incompatible. The good one can be cloned from
git://git.criu.org/iproute2. It should be compiled and a path
to ip is written in \$CR_IP_TOOL.
EOF
			exit 1;
		}
		args="-n uts -n ipc -n net -n pid -n mnt --root $ZDTM_ROOT --pidfile $TPID $args"
	fi

	for i in `seq $ITERATIONS`; do

	ddump=dump/$tname/$PID/$i
	DUMP_PATH=`pwd`/$ddump
	echo Dump $PID
	mkdir -p $ddump

	save_fds $PID  $ddump/dump.fd
	setsid $CRTOOLS dump --tcp-established --link-remap -x --evasive-devices -D $ddump -o dump.log -v 4 -t $PID $args $ARGS || {
		echo WARNING: process $tname is left running for your debugging needs
		return 1
	}
	if expr " $ARGS" : ' -s' > /dev/null; then
		save_fds $PID  $ddump/dump.fd.after
		diff_fds $ddump/dump.fd $ddump/dump.fd.after || return 1
		killall -CONT $tname
	else
		# Wait while tasks are dying, otherwise PIDs would be busy.
		for i in $ddump/core-*.img; do
			local pid

			[ -n "$PIDNS" ] && break;

			pid=`expr "$i" : '.*/core-\([0-9]*\).img'`
			while :; do
				kill -0 $pid > /dev/null 2>&1 || break;
				echo Waiting the process $pid
				sleep 0.1
			done
		done

		echo Restore $PID
		setsid $CRTOOLS restore --tcp-established -x -D $ddump -o restore.log -v 4 -d -t $PID $args || return 2

		for i in `seq 5`; do
			save_fds $PID  $ddump/restore.fd
			diff_fds $ddump/dump.fd $ddump/restore.fd && break
			sleep 0.2
		done
		[ $i -eq 5 ] && return 2;
		[ -n "$PIDNS" ] && PID=`cat $TPID`
	fi

	done

	echo Check results $PID
	stop_test $tdir $tname
	sltime=1
	for i in `seq 50`; do
		test -f $test.out && break
		echo Waiting...
		sleep 0.$sltime
		[ $sltime -lt 9 ] && sltime=$((sltime+1))
	done
	cat $test.out
	cat $test.out | grep -q PASS || return 2
}

case_error()
{
	test=${ZP}/${1#ns/}
	local test_log=`pwd`/$test.out

	echo "Test: $test"
	echo "====================== ERROR ======================"

	if [ -n "$DUMP_PATH" ]; then
		[ -e "$DUMP_PATH/dump.log" ] && {
			echo "Dump log   : $DUMP_PATH/dump.log"
			cat $DUMP_PATH/dump.log* | grep Error
		}
		[ -e "$DUMP_PATH/restore.log" ] && {
			echo "Restore log: $DUMP_PATH/restore.log"
			cat $DUMP_PATH/restore.log* | grep Error
		}
	fi
	[ -e "$test_log" ] &&
		echo "Output file: $test_log"
	exit 1
}

cd `dirname $0` || exit 1

while :; do
	if [ "$1" = "-d" ]; then
		ARGS="-s"
		shift
		continue
	fi
	if [ "$1" = "-i" ]; then
		shift
		ITERATIONS=$1
		shift
		continue
	fi
	break;
done

if [ $# -eq 0 ]; then

	check_mainstream || exit 1

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
elif [ "$1" = "-l" ]; then
	echo $TEST_LIST $UTS_TEST_LIST $MNT_TEST_LIST $IPC_TEST_LIST | tr ' ' '\n'
elif [ "$1" = "-h" ]; then
	cat >&2 <<EOF
This script is used for executing unit tests.
Usage:
zdtm.sh [OPTIONS]
zdtm.sh [OPTIONS] [TEST NAME]
Options:
	-l : Show list of tests.
	-d : Dump a test process and check that this process can continue working.
	-i : Number of ITERATIONS of dump/restore
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
