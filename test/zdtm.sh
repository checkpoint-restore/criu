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
static/maps02
static/maps04
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
static/file_append
static/timers
static/posix_timers
static/futex
static/futex-rl
static/xids00
static/groups
static/pthread00
static/pthread01
static/umask00
streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
static/sockets00
static/sockets01
static/sockets02
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
static/fanotify00
static/unbound_sock
static/fifo-rowo-pair
static/fifo-ghost
static/fifo
static/fifo_wronly
static/zombie00
static/rlimits00
transition/fork
static/pty00
static/pty01
static/pty04
static/tty02
static/tty03
static/child_opened_proc
static/cow01
static/fpu00
static/fpu01
static/mmx00
static/sse00
static/sse20
static/fdt_shared
static/file_locks00
static/file_locks01
static/sigpending
static/sigaltstack
static/sk-netlink
static/proc-self
static/grow_map
static/grow_map02
static/stopped
static/chroot
static/chroot-file
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
static/socket-tcpbuf-local
static/socket-tcpbuf6
static/pty03
static/mountpoints
ns/static/session00
ns/static/session01
static/utsname
static/ipc_namespace
static/shm
static/msgque
static/sem
transition/ipc
ns/static/tun
static/netns-nf
static/netns
"

TEST_CR_KERNEL="
ns/static/tun
"

TEST_SUID_LIST="
pid00
caps00
maps01
groups
sched_prio00
sched_policy00
sock_opts00
sock_opts01
cmdlinenv00
packet_sock
fanotify00
sk-netlink
tun
chroot
chroot-file
"

source $(readlink -f `dirname $0`/env.sh) || exit 1

CRIU_CPT=$CRIU
TMP_TREE=""
SCRIPTDIR=`dirname $CRIU`/test
POSTDUMP="--action-script $SCRIPTDIR/post-dump.sh"

ARGS=""

PID=""
PIDNS=""

ITERATIONS=1
EXCLUDE_PATTERN=""
CLEANUP=0
PAGE_SERVER=0
PS_PORT=12345
COMPILE_ONLY=0
BATCH_TEST=0
SPECIFIED_NAME_USED=0

check_criu()
{
	if [ ! -x $CRIU ]; then
		echo "$CRIU is unavailable"
		return 1
	fi
}

check_mainstream()
{
	local -a ver_arr
	local ver_str=`uname -r`

	cat >&2 <<EOF
========================== CRIU CHECK =============================
EOF

	$CRIU check && return 0
	MAINSTREAM_KERNEL=1

	cat >&2 <<EOF
============================= WARNING =============================
Not all features needed for CRIU are merged to upstream kernel yet,
so for now we maintain our own branch which can be cloned from:
git://git.kernel.org/pub/scm/linux/kernel/git/gorcunov/linux-cr.git
===================================================================
EOF

	ver_arr=(`echo ${ver_str//./ }`)

	[ "${ver_arr[0]}" -gt 3 ] && return 0
	[[ "${ver_arr[0]}" -eq 3 && "${ver_arr[1]}" -ge 11 ]] && return 0

	echo "A version of kernel should be greater or equal to 3.11" >&2

	return 1
}

exit_callback()
{
	echo $@
	if [ -n "$ZDTM_ROOT" ]; then
		umount -l "$ZDTM_ROOT"
		rmdir "$ZDTM_ROOT"
	fi

	[[ -n "$ZDTM_FAILED" && -n "$DUMP_ARCHIVE" ]] && tar -czf $DUMP_ARCHIVE dump
	[ -n "$TMPFS_DUMP" ] &&
		umount -l "$TMPFS_DUMP"
}
trap exit_callback EXIT

construct_root()
{
	local root=$1
	local test_path=$2
	local ps_path=`type -P ps`
	local libdir=$root/lib
	local libdir2=$root/lib64
	local tmpdir=$root/tmp
	local lname tname

	mkdir -p $root/bin
	cp $ps_path $root/bin

	mkdir -p $libdir $libdir2

	# $ ldd /bin/ps test/zdtm/live/static/env00
	# /bin/ps:
	#	/usr/lib/arm-linux-gnueabihf/libcofi_rpi.so (0xb6f39000)
	#	libprocps.so.0 => /lib/arm-linux-gnueabihf/libprocps.so.0 (0xb6f04000)
	#	libgcc_s.so.1 => /lib/arm-linux-gnueabihf/libgcc_s.so.1 (0xb6edc000)
	#	libc.so.6 => /lib/arm-linux-gnueabihf/libc.so.6 (0xb6dad000)
	#	/lib/ld-linux-armhf.so.3 (0xb6f46000)
	# test/zdtm/live/static/env00:
	#	/usr/lib/arm-linux-gnueabihf/libcofi_rpi.so (0xb6efe000)
	#	libc.so.6 => /lib/arm-linux-gnueabihf/libc.so.6 (0xb6dc5000)
	#	/lib/ld-linux-armhf.so.3 (0xb6f0b000)

	for i in `ldd $test_path $ps_path | grep -P '^\s' | grep -v vdso | sed "s/.*=> //" | awk '{ print $1 }'`; do
		local ldir lib=`basename $i`

		[ -f $libdir2/$lib ] && continue # fast path

		if [ -f $i ]; then
			lname=$i
		elif [ -f /lib64/$i ]; then
			lname=/lib64/$i
		elif [ -f /usr/lib64/$i ]; then
			lname=/usr/lib64/$i
		elif [ -f /lib/x86_64-linux-gnu/$i ]; then
			lname=/lib/x86_64-linux-gnu/$i
		elif [ -f /lib/arm-linux-gnueabi/$i ]; then
			lname=/lib/arm-linux-gnueabi/$i
		else
			echo "Failed at " $i
			return 1
		fi

		# When tests are executed concurrently all of them use the same root,
		# so libraries must be copied atomically.

		for ldir in "$libdir" "$libdir2"; do
			tname=$(mktemp $ldir/lib.XXXXXX)
			cp -pf $lname $tname &&
			mv -n $tname $ldir/$lib || return 1
			[ -f $tname ] && unlink $tname
		done
	done

	# make 'tmp' dir under new root
	mkdir -p $tmpdir
	chmod 0777 $tmpdir
}

export MAKEFLAGS=--no-print-directory

start_test()
{
	local tdir=$1
	local tname=$2
	export ZDTM_ROOT
	TPID=`readlink -f $tdir`/$tname.init.pid

	killall -9 $tname > /dev/null 2>&1
	make -C $tdir $tname.cleanout

	unset ZDTM_UID
	unset ZDTM_GID

	if ! echo $TEST_SUID_LIST | grep -q $tname; then
		export ZDTM_UID=18943
		export ZDTM_GID=58467
		chown $ZDTM_UID:$ZDTM_GID $tdir
	fi

	if [ -z "$PIDNS" ]; then
		make -C $tdir $tname.pid || return 1
		PID=`cat $test.pid` || return 1
	else
		if [ -z "$ZDTM_ROOT" ]; then
			mkdir -p dump
			ZDTM_ROOT=`mktemp -d /tmp/criu-root.XXXXXX`
			ZDTM_ROOT=`readlink -f $ZDTM_ROOT`
			mount --bind . $ZDTM_ROOT || return 1
		fi
		make -C $tdir $tname || return 1
		construct_root $ZDTM_ROOT $tdir/$tname || return 1
	(	export ZDTM_NEWNS=1
		export ZDTM_PIDFILE=$TPID
		cd $ZDTM_ROOT
		rm -f $ZDTM_PIDFILE
		if ! make -C $tdir $tname.pid; then
			echo ERROR: fail to start $tdir/$tname
			return 1
		fi
	)

		PID=`cat "$TPID"`
		ps -p $PID || return 1
	fi
}

stop_test()
{
	kill $PID
}

save_fds()
{
	test -n "$PIDNS" && return 0
	ls -l /proc/$1/fd | sed 's/\(-> \(pipe\|socket\)\):.*/\1/' | awk '{ print $9,$10,$11; }' > $2
}

save_maps()
{
	cat /proc/$1/maps | python maps.py > $2
}

diff_maps()
{
	if ! diff -up $1 $2; then
		echo ERROR: Sets of mappings differ:
		echo $1
		echo $2
		return 1
	fi
}

diff_fds()
{
	test -n "$PIDNS" && return 0
	if ! diff -up $1 $2; then
		echo ERROR: Sets of descriptors differ:
		echo $1
		echo $2
		return 1
	fi
}

run_test()
{
	local test=$1
	local linkremap=
	local snapopt=
	local snappdir=
	local ps_pid=

	[ -n "$EXCLUDE_PATTERN" ] && echo $test | grep "$EXCLUDE_PATTERN" && return 0

	#
	# add option for unlinked files test
	if [[ $1 =~ "unlink_" ]]; then
		linkremap="--link-remap"
	fi

	if [ -n "$MAINSTREAM_KERNEL" ] && [ $COMPILE_ONLY -eq 0 ] && echo $TEST_CR_KERNEL | grep -q ${test#ns/}; then
		echo "Skip $test"
		return 0
	fi

	expr "$test" : 'ns/' > /dev/null && PIDNS=1 || PIDNS=""
	test=${ZP}/${test#ns/}

	shift
	local args=$*
	local tname=`basename $test`
	local tdir=`dirname $test`
	DUMP_PATH=""

	if [ $COMPILE_ONLY -eq 1 ]; then
		echo "Compile $test"
		make -C $tdir $tname && return 0 || return 1
	fi

	echo "Execute $test"

	start_test $tdir $tname || return 1

	local ddump
	if ! kill -s 0 "$PID"; then
		echo "Got a wrong pid '$PID'"
		return 1
	fi

	if [ -n "$PIDNS" ]; then
		[ -z "$CR_IP_TOOL" ] && CR_IP_TOOL=ip
		if ! $CR_IP_TOOL a help 2>&1 | grep -q showdump; then
			cat >&2 <<EOF
The util "ip" is incompatible. The good one can be cloned from
git://git.criu.org/iproute2. It should be compiled and a path
to ip is written in \$CR_IP_TOOL.
EOF
			exit 1
		fi
		args="--root $ZDTM_ROOT --pidfile $TPID $args"
	fi

	for i in `seq $ITERATIONS`; do
		local dump_only=
		local postdump=
		ddump=dump/$tname/$PID/$i
		DUMP_PATH=`pwd`/$ddump
		echo Dump $PID
		mkdir -p $ddump

		[ -n "$DUMP_ONLY" ] && dump_only=1

		if [ $PAGE_SERVER -eq 1 ]; then
			$CRIU page-server -D $ddump -o page_server.log -v4 --port $PS_PORT --daemon || return 1
			ps_pid=`lsof -s TCP:LISTEN -i :$PS_PORT -t`
			ps -p "$ps_pid" -o cmd h | grep -q page-server || {
				echo "Unable to determing PID of page-server"
				return 1
			}
			opts="--page-server --address 127.0.0.1 --port $PS_PORT"
		fi

		if [ -n "$SNAPSHOT" ]; then
			snapopt=""
			if [ "$i" -ne "$ITERATIONS" ]; then
				snapopt="$snapopt -R --track-mem"
				dump_only=1
			fi
			[ -n "$snappdir" ] && snapopt="$snapopt --prev-images-dir=$snappdir"
		fi

		[ -n "$dump_only" ] && postdump=$POSTDUMP

		save_fds $PID  $ddump/dump.fd
		save_maps $PID  $ddump/dump.maps
		setsid $CRIU_CPT dump $opts --file-locks --tcp-established $linkremap \
			-x --evasive-devices -D $ddump -o dump.log -v4 -t $PID $args $ARGS $snapopt $postdump
		retcode=$?

		#
		# Here we may have two cases: either checkpoint is failed
		# with some error code, or checkpoint is complete but return
		# code is non-zero because of post dump action.
		if [ "$retcode" -ne 0 ] && [[ "$retcode" -ne 32 || -z "$dump_only" ]]; then
			if [ $BATCH_TEST -eq 0 ]; then
				echo WARNING: $tname returned $retcode and left running for debug needs
			else
				echo WARNING: $tname failed and returned $retcode
			fi
			return 1
		fi

		if [ -n "$SNAPSHOT" ]; then
			snappdir=../`basename $ddump`
			[ "$i" -ne "$ITERATIONS" ] && continue
		fi

		if [ $PAGE_SERVER -eq 1 ]; then
			while :; do
				kill -0 $ps_pid > /dev/null 2>&1 || break
				echo Waiting the process $ps_pid
				sleep 0.1
			done
		fi

		if [ -n "$dump_only" ]; then
			save_fds $PID  $ddump/dump.fd.after
			diff_fds $ddump/dump.fd $ddump/dump.fd.after || return 1

			save_maps $PID  $ddump/dump.maps.after
			diff_maps $ddump/dump.maps $ddump/dump.maps.after || return 1

			if [[ $linkremap ]]; then
				echo "remove ./$tdir/link_remap.*"
				rm -f ./$tdir/link_remap.*
			fi
		else
			# Wait while tasks are dying, otherwise PIDs would be busy.
			for i in $ddump/core-*.img; do
				local pid

				[ -n "$PIDNS" ] && break

				pid=`expr "$i" : '.*/core-\([0-9]*\).img'`
				while :; do
					kill -0 $pid > /dev/null 2>&1 || break
					echo Waiting the process $pid
					sleep 0.1
				done
			done

			echo Restore
			setsid $CRIU restore --file-locks --tcp-established -x -D $ddump -o restore.log -v4 -d $args || return 2

			[ -n "$PIDNS" ] && PID=`cat $TPID`
			for i in `seq 5`; do
				save_fds $PID  $ddump/restore.fd
				diff_fds $ddump/dump.fd $ddump/restore.fd && break
				sleep 0.2
			done
			[ $i -eq 5 ] && return 2

			save_maps $PID $ddump/restore.maps
			diff_maps $ddump/dump.maps $ddump/restore.maps || return 2
		fi

	done

	echo Check results $PID
	if ! stop_test $tdir $tname; then
		echo "Unable to stop $tname ($PID)"
		return 2
	fi

	sltime=1
	for i in `seq 50`; do
		kill -0 $PID > /dev/null 2>&1 || break
		echo Waiting...
		sleep 0.$sltime
		[ $sltime -lt 9 ] && sltime=$((sltime+1))
	done

	cat $test.out
	cat $test.out | grep -q PASS || return 2
	[ "$CLEANUP" -ne 0 ] && rm -rf `dirname $ddump`
	echo "Test: $test, Result: PASS"
	return 0
}

case_error()
{
	test=${ZP}/${1#ns/}
	local test_log=`pwd`/$test.out

	echo "Test: $test, Result: FAIL"
	ZDTM_FAILED=1

(	exec >&2

	cat <<EOF
============================= ERROR ===============================
EOF

	echo "Test: $test, Namespace: $PIDNS"
	cat <<EOF
-------------------------------------------------------------------
EOF

	if [ -n "$DUMP_PATH" ]; then
		if [ -e "$DUMP_PATH/dump.log" ]; then
			echo "Dump log   : $DUMP_PATH/dump.log"
			cat $DUMP_PATH/dump.log* | grep Error
			cat <<EOF
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
EOF
			tail -n 40 $DUMP_PATH/dump.log*
			cat <<EOF
-------------------------------------------------------------------
EOF
		fi
		if [ -e "$DUMP_PATH/restore.log" ]; then
			echo "Restore log: $DUMP_PATH/restore.log"
			cat $DUMP_PATH/restore.log* | grep Error
			cat <<EOF
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
EOF
			tail -n 40 $DUMP_PATH/restore.log*
			cat <<EOF
-------------------------------------------------------------------
EOF
		fi
	fi
	if [ -e "$test_log" ]; then
		echo "Output file: $test_log"
		cat $test_log*
		cat <<EOF
-------------------------------------------------------------------
EOF
	fi

	[ -n "$HEAD" ] &&
		echo "The initial HEAD was $HEAD"

	cat <<EOF
=========================== ERROR OVER ============================
EOF
)
	if [ $BATCH_TEST -eq 0 ]; then
		exit 1
	else
		# kill failed test
		local tname=`basename $test`
		killall -9 $tname > /dev/null 2>&1
	fi
}

checkout()
{
	local commit=`git describe $1` &&
	TMP_TREE=`dirname $CRIU`/criu.$commit &&
	mkdir -p $TMP_TREE &&
	git --git-dir `dirname $CRIU`/.git archive $commit . | tar -x -C $TMP_TREE &&
	make -C $TMP_TREE -j 32
}

usage() {
	cat << EOF
This script is used for executing unit tests.
Usage:
zdtm.sh [OPTIONS]
zdtm.sh [OPTIONS] [TEST PATTERN]
Options:
	-l : Show list of tests.
	-d : Dump a test process and check that this process can continue working.
	-i : Number of ITERATIONS of dump/restore
	-p : Test page server
	-C : Delete dump files if a test completed successfully
	-b <commit> : Check backward compatibility
	-x <PATTERN>: Exclude pattern
	-t : mount tmpfs for dump files
	-a <FILE>.tar.gz : save archive with dump files and logs
	-g : Generate executables only
	-n : Batch test
	-r : Run test with specified name directly without match or check
EOF
}

cd `dirname $0` || exit 1

while :; do
	case $1 in
	  -d)
		DUMP_ONLY=1
		shift
		;;
	  -i)
		shift
		ITERATIONS=$1
		shift
		;;
	  -b)
		shift
		checkout $1 || exit 1
		CRIU_CPT=$TMP_TREE/criu
		shift
		;;
	  -c)
		shift
		checkout $1 || exit 1
		shift
		$TMP_TREE/test/zdtm.sh "$@"
		exit
		;;
	  -p)
		shift
		PAGE_SERVER=1
		;;
	  -C)
		shift
		CLEANUP=1
		;;
	  -x)
		shift
		EXCLUDE_PATTERN=$1
		shift
		;;
	  -t)
		shift
		TMPFS_DUMP=dump
		[ -d dump ] || mkdir -p $TMPFS_DUMP
		mount -t tmpfs none $TMPFS_DUMP || exit 1
		;;
	  -a)
		shift
		DUMP_ARCHIVE=$1
		shift
		;;
	  -s)
		SNAPSHOT=1
		shift
		;;
	  -g)
		COMPILE_ONLY=1
		shift
		;;
	  -n)
		BATCH_TEST=1
		shift
		;;
	  -r)
		SPECIFIED_NAME_USED=1
		shift
		;;
	  -l)
		echo $TEST_LIST | tr ' ' '\n'
		exit 0
		;;
	  -h)
		usage
		exit 0
		;;
	  -*)
		echo "Unrecognized option $1, aborting!" 1>&2
		usage
		exit 1
		;;
	  *)
		break
		;;
	esac
done

if [ $# -gt 1 ]; then
	echo "Too many arguments: $*" 1>&2
	exit 1
fi

if [ $COMPILE_ONLY -eq 0 ]; then
	check_criu || exit 1
fi

if [ $SPECIFIED_NAME_USED -eq 1 ]; then
	if [ $# -eq 0 ]; then
		echo "test name should be provided"
		exit 1
	fi
	run_test $1 || case_error $1
else
	if [ $COMPILE_ONLY -eq 0 ]; then
		check_mainstream || exit 1
	fi

	if [ $# -eq 0 ]; then
		pattern='.*'
	else
		pattern=$1
	fi

	for t in $(echo "$TEST_LIST" | grep -x "$pattern"); do
		run_test $t || case_error $t
	done

	if [ $COMPILE_ONLY -eq 0 ]; then
		if [ -n "$ZDTM_FAILED" ]; then
			echo ZDTM tests FAIL.
		else
			echo ZDTM tests PASS.
		fi
	fi
fi

[ -n "$TMP_TREE" ] && rm -rf $TMP_TREE
[ -n "$ZDTM_FAILED" ] && exit 1 || exit 0
