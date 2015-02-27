#!/bin/bash

# duplicate stdout into 3
exec 3<&1
# duplicate stderr into stdout
exec 1>&2

ARCH=`uname -m | sed			\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/ppc.*/powerpc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/`

ZP="zdtm/live"

source $(readlink -f `dirname $0`/env.sh) || exit 1

generate_test_list()
{

	check_mainstream || exit 1

	TEST_LIST="
		static/pipe00
		static/pipe01
		static/pipe02
		static/busyloop00
		static/cwd00
		static/cwd01
		static/cwd02
		static/env00
		static/maps00
		static/maps01
		static/maps02
		static/maps04
		static/maps05
		static/mlock_setuid
		static/maps_file_prot
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
		static/deleted_unix_sock
		static/sk-unix-unconn
		static/pid00
		static/pstree
		static/caps00
		static/cmdlinenv00
		static/socket_listen
		static/socket_listen6
		static/packet_sock
		static/packet_sock_mmap
		static/socket_udp
		static/sock_filter
		static/socket6_udp
		static/socket_udplite
		static/selfexe00
		static/link10
		static/unlink_fstat00
		static/unlink_fstat01
		static/unlink_fstat02
		static/unlink_fstat03
		static/unlink_mmap00
		static/unlink_mmap01
		static/unlink_mmap02
		static/rmdir_open
		static/eventfs00
		static/signalfd00
		static/inotify00
		static/inotify_irmap
		static/fanotify00
		static/unbound_sock
		static/fifo-rowo-pair
		static/fifo-ghost
		static/fifo
		static/fifo_wronly
		static/fifo_ro
		static/unlink_fifo
		static/unlink_fifo_wronly
		static/zombie00
		static/rlimits00
		transition/fork
		transition/fork2
		transition/thread-bomb
		static/pty00
		static/pty01
		static/pty04
		static/tty02
		static/tty03
		static/console
		static/vt
		static/child_opened_proc
		static/cow01
		static/fpu00
		static/fpu01
		static/mmx00
		static/sse00
		static/sse20
		static/pdeath_sig
		static/fdt_shared
		static/file_locks00
		static/file_locks01
		static/file_locks02
		static/file_locks03
		static/file_locks04
		static/file_locks05
		static/sigpending
		static/sigaltstack
		static/sk-netlink
		static/proc-self
		static/grow_map
		static/grow_map02
		static/grow_map03
		static/stopped
		static/chroot
		static/chroot-file
		static/rtc
		transition/maps007
		static/dumpable01
		static/dumpable02
		static/deleted_dev
	"

	#
	# Arch specific tests
	if [ $ARCH = "x86_64" ]; then
		TEST_LIST_ARCH="
			static/vdso01
		"
	fi

	TEST_LIST=$TEST_LIST$TEST_LIST_ARCH

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
		ns/static/tempfs
		ns/static/bind-mount
		static/utsname
		static/ipc_namespace
		static/shm
		static/msgque
		static/sem
		transition/ipc
		static/netns-nf
		static/netns
		static/cgroup00
		static/cgroup01
		static/cgroup02
		ns/static/clean_mntns
		static/remap_dead_pid
	"

	TEST_CR_KERNEL="
	"

	TEST_MNTNS="
		ns/static/mntns_open
		ns/static/mntns_link_remap
		ns/static/mntns_link_ghost
		ns/static/mntns_shared_bind
		ns/static/mntns_shared_bind02
		ns/static/mntns_root_bind
	"

	TEST_AIO="
		static/aio00
		ns/static/aio00
	"

	TEST_TIMERFD="
		static/timerfd
		ns/static/timerfd
	"

	TEST_TUN="
		ns/static/tun
	"

	$CRIU check -v0 --feature "mnt_id"
	if [ $? -eq 0 ]; then
		TEST_LIST="$TEST_LIST$TEST_MNTNS"
	else
		export ZDTM_NOSUBNS=1
	fi

	$CRIU check -v0 --feature "aio_remap"
	if [ $? -eq 0 ]; then
		TEST_LIST="$TEST_LIST$TEST_AIO"
	fi

	$CRIU check -v0 --feature "timerfd"
	if [ $? -eq 0 ]; then
		TEST_LIST="$TEST_LIST$TEST_TIMERFD"
	fi

	$CRIU check -v0 --feature "tun"
	if [ $? -eq 0 ]; then
		TEST_LIST="$TEST_LIST$TEST_TUN"
	fi

	BLACKLIST_FOR_USERNS="
		ns/static/maps01
		ns/static/mlock_setuid
		ns/static/sched_prio00
		ns/static/sched_policy00
		ns/static/fanotify00
		ns/static/dumpable02
		ns/static/deleted_dev
		ns/static/tempfs
		ns/static/clean_mntns
		ns/static/mntns_link_remap
		ns/static/mntns_link_ghost
		ns/static/console
		ns/static/vt
		ns/static/rtc
		ns/static/mntns_shared_bind
		ns/static/mntns_shared_bind02
		ns/static/mntns_root_bind
	"

	# Add tests which can be executed in an user namespace
	$CRIU check -v0 --feature "userns"
	if [ $? -eq 0 ]; then
		blist=`mktemp /tmp/zdtm.black.XXXXXX`
		echo "$BLACKLIST_FOR_USERNS" | tr -d "[:blank:]" | sort > $blist


		TEST_LIST="$TEST_LIST
		`echo "$TEST_LIST" | tr -d "[:blank:]" | grep "^ns/" | sort | \
		diff --changed-group-format="%<" --unchanged-group-format="" - $blist | \
		sed s#ns/#ns/user/#`"
		unlink $blist
	fi

	TEST_LIST=$(echo $TEST_LIST | tr " " "\n")
}

TEST_SUID_LIST="
pid00
caps00
maps01
mlock_setuid
groups
sched_prio00
sched_policy00
sock_opts00
sock_opts01
cmdlinenv00
packet_sock
packet_sock_mmap
fanotify00
sk-netlink
tun
chroot
chroot-file
console
vt
rtc
tempfs
maps007
tempfs
bind-mount
mountpoints
inotify_irmap
cgroup00
cgroup01
cgroup02
clean_mntns
deleted_dev
mntns_open
mntns_link_remap
mntns_link_ghost
mntns_shared_bind
mntns_shared_bind02
mntns_root_bind
sockets00
"

CRIU_CPT=$CRIU
TMP_TREE=""
SCRIPTDIR=`dirname $CRIU`/test
POSTDUMP="--action-script $SCRIPTDIR/post-dump.sh"
VERBOSE=0

PID=""
PIDNS=""

ITERATIONS=1
EXCLUDE_PATTERN=""
CLEANUP=0
PAGE_SERVER=0
PS_PORT=12345
COMPILE_ONLY=0
START_ONLY=0
BATCH_TEST=0
SPECIFIED_NAME_USED=0
START_FROM="."

zdtm_sep()
{ (
	set +x
	local msg=$1
	[ -n "$msg" ] && msg=" $msg "
	awk -v m=${2:-=} -v "msg=$msg" '
		BEGIN {
			l=length(msg);
			s=int((79-l)/2);
			sep = sprintf("%"s"s", " ")
			gsub(/ /, m, sep);
			printf("%s%s%s\n",sep,msg,sep);
		}' < /dev/null
) }

check_criu()
{
	if [ ! -x $CRIU ]; then
		echo "$CRIU is unavailable"
		return 1
	fi
}

check_mainstream()
{
	zdtm_sep "CRIU CHECK"

	$CRIU check -v1 && return 0
	MAINSTREAM_KERNEL=1

	cat >&2 <<EOF
============================= WARNING =============================
Not all features needed for CRIU are merged to upstream kernel yet,
so for now we maintain our own branch which can be cloned from:
git://git.kernel.org/pub/scm/linux/kernel/git/gorcunov/linux-cr.git
===================================================================
EOF

	set -- `uname -r | sed 's/[\.-]/ /g'`

	[ $1 -gt 3 ] && return 0
	[ $1 -eq 3 -a $2 -ge 11 ] && return 0

	echo "Kernel version should be greater than or equal to 3.11" >&2

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

	local libs=$(ldd $test_path $ps_path | awk '
		!/^[ \t]/ { next }
		/\<linux-vdso\.so\>/ { next }
		/\<linux-gate\.so\>/ { next }
		/\<not a dynamic executable$/ { next }
		$2 ~ /^=>$/ { print $3; next }
		{ print $1 }
	')
	for i in ${libs}; do
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
	local test=$(readlink -f $tdir)/$tname
	export ZDTM_ROOT

	killall -9 $tname > /dev/null 2>&1
	make -C $tdir $tname.cleanout

	unset ZDTM_UID
	unset ZDTM_GID
	unset ZDTM_GROUPS

	if ! echo $TEST_SUID_LIST | grep -q $tname; then
		export ZDTM_UID=18943
		export ZDTM_GID=58467
		export ZDTM_GROUPS="27495 48244"
		chmod a+w $tdir
	fi

	if [ -z "$USERNS" ]; then
		unset ZDTM_USERNS
	else
		# we need to be able to create a temporary directory in a test
		# root for restoring mount namespaces
		chmod go+wxr .
		export ZDTM_USERNS=1
	fi

	if [ -z "$PIDNS" ]; then
		TPID="$test.pid"
		unset ZDTM_NEWNS
	else
		TPID=$test.init.pid
		if [ -z "$ZDTM_ROOT" ]; then
			mkdir -p dump
			ZDTM_ROOT=`mktemp -d /tmp/criu-root.XXXXXX`
			ZDTM_ROOT=`readlink -f $ZDTM_ROOT`
			mount --make-private --bind . $ZDTM_ROOT || return 1
		fi
		construct_root $ZDTM_ROOT $test || return 1
		export ZDTM_NEWNS=1
		export ZDTM_PIDFILE=$TPID
		cd $ZDTM_ROOT
		rm -f $ZDTM_PIDFILE
	fi

	(
		# Here is no way to set FD_CLOEXEC on 3
		exec 3>&-
		make -C $tdir $tname.pid
	)

	if [ $? -ne 0 ]; then
		echo ERROR: fail to start $test
		return 1
	fi

	[ -z "$PIDNS" ] || cd -

	PID=`cat "$TPID"` || return 1
	if ! kill -0 $PID ; then
		echo "Test failed to start"
		return 1
	fi
}

stop_test()
{
	kill $PID
}

save_fds()
{
	test -z "$PIDNS" && return 0
	echo -n > $2 # Busybox doesn't have truncate
	for p in `ls /proc/$1/root/proc/ | grep "^[0-9]*$"`; do
		ls -l /proc/$1/root/proc/$p/fd |
			sed 's/\(-> \(pipe\|socket\)\):.*/\1/' |
			sed -e 's/\/.nfs[0-9a-zA-Z]*/.nfs-silly-rename/' |
			sed 's/net:\[[0-9].*\]/net/' |
			awk '{ print $9,$10,$11; }' | sort >> $2
	done
}

save_maps()
{
	test -z "$PIDNS" && return 0
	echo -n > $2 # Busybox doesn't have truncate
	for p in `ls /proc/$1/root/proc/ | grep "^[0-9]*$"`; do
		cat /proc/$1/root/proc/$p/maps | python maps.py >> $2
	done
}

diff_maps()
{
	test -z "$PIDNS" && return 0
	if ! diff -up $1 $2; then
		echo ERROR: Sets of mappings differ:
		echo $1
		echo $2
		return 1
	fi
}

diff_fds()
{
	test -z "$PIDNS" && return 0
	if ! diff -up $1 $2; then
		echo ERROR: Sets of descriptors differ:
		echo $1
		echo $2
		return 1
	fi
}

run_test()
{
	local test_name=$1
	local test=$1
	local snappdir=
	local ps_pid=

	[ -n "$EXCLUDE_PATTERN" ] && echo $test | grep "$EXCLUDE_PATTERN" && return 0

	if [ -n "$MAINSTREAM_KERNEL" ] && [ $COMPILE_ONLY -eq 0 ]; then
		if echo $TEST_CR_KERNEL | grep -q ${test#ns/}; then
			echo "Skip $test"
			return 0
		fi
		expr $test : 'ns/user' > /dev/null && {
			echo "Skip $test"
			return 0
		}
	fi

	expr "$test" : 'ns/' > /dev/null && PIDNS=1 || PIDNS=""
	test=${test#ns/}
	expr "$test" : 'user/' > /dev/null && USERNS=1 || USERNS=""
	test=${test#user/}
	test=${ZP}/${test}

	shift
	local gen_args=$*
	local tname=`basename $test`
	local tdir=`dirname $test`
	DUMP_PATH=""

	if [ $COMPILE_ONLY -eq 1 ]; then
		echo "Compile $test"
		make -C $tdir $tname && return 0 || return 1
	fi

	echo "Execute $test_name"

	start_test $tdir $tname || return 1

	if [ $START_ONLY -eq 1 ]; then
		echo "Test is started"
		return 0
	fi

	local ddump

	if [ -f "${test}.opts" ]; then
		gen_args="$gen_args $(cat "${test}.opts")"
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
		gen_args="--root $ZDTM_ROOT --pidfile $TPID $gen_args"
	fi

	if [ $tname = "rtc" ]; then
		gen_args="$gen_args -L `pwd`/$tdir/lib"
	fi

	if [ -n "$AUTO_DEDUP" ]; then
		gen_args="$gen_args --auto-dedup"
		ps_args="--auto-dedup"
	fi

	if echo $tname | fgrep -q 'irmap'; then
		gen_args="$gen_args --force-irmap"
	fi

	# X will be substituted with an iteration number
	ddump=`pwd`/dump/$test_name/$PID/X
	for i in `seq $ITERATIONS`; do
		local cpt_args=
		local dump_only=
		local dump_cmd="dump"
		ddump=`dirname $ddump`/$i
		DUMP_PATH=$ddump
		echo Dump $PID
		mkdir -p $ddump

		[ -n "$DUMP_ONLY" ] && dump_only=1

		if [ $PAGE_SERVER -eq 1 ]; then
			$CRIU page-server -D $ddump -o page_server.log -v4 --port $PS_PORT $ps_args --daemon --pidfile $ddump/page-server.pid || return 1
			ps_pid=`cat $ddump/page-server.pid`
			ps -p "$ps_pid" -o cmd h | grep -q page-server || {
				echo "Unable to determing PID of page-server"
				return 1
			}
			cpt_args="$cpt_args --page-server --address 127.0.0.1 --port $PS_PORT"
		fi

		if [ -n "$SNAPSHOT" ]; then
			cpt_args="$cpt_args --track-mem"
			if [ "$i" -ne "$ITERATIONS" ]; then
				cpt_args="$cpt_args -R"
				dump_only=1
				[ -n "$PRE_DUMP" ] && dump_cmd="pre-dump"
			fi
			[ -n "$snappdir" ] && cpt_args="$cpt_args --prev-images-dir=$snappdir"
		fi

		[ -n "$dump_only" ] && cpt_args="$cpt_args $POSTDUMP"

		expr $tdir : ".*static$" > /dev/null && {
			save_fds $PID  $ddump/dump.fd
			save_maps $PID  $ddump/dump.maps
		}
		setsid $CRIU_CPT $dump_cmd -D $ddump -o dump.log -v4 -t $PID $gen_args $cpt_args
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
		cat $ddump/dump.log* | grep Error

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
			expr $tdir : ".*static$" > /dev/null && {
				save_fds $PID  $ddump/dump.fd.after
				diff_fds $ddump/dump.fd $ddump/dump.fd.after || return 1

				save_maps $PID  $ddump/dump.maps.after
				diff_maps $ddump/dump.maps $ddump/dump.maps.after || return 1
			}

			rm -f ./$tdir/link_remap.*
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

			if [ -x "${test}.hook" ]; then
				echo "Executing pre-restore hook"
				"${test}.hook" --pre-restore || return 2
			fi

			# Restore fails if --pidfile exists, so remove it.
			rm -f $TPID || true

			echo Restore
			setsid $CRIU restore -D $ddump -o restore.log -v4 -d $gen_args || return 2
			cat $ddump/restore.log* | grep Error

			[ -n "$PIDNS" ] && PID=`cat $TPID`

			expr $tdir : ".*static$" > /dev/null && {
				save_fds $PID  $ddump/restore.fd
				save_maps $PID $ddump/restore.maps
				diff_fds $ddump/dump.fd $ddump/restore.fd || return 2
				diff_maps $ddump/dump.maps $ddump/restore.maps || return 2
			}
			[ "$CLEANUP" -ne 0 ] && rm -f --one-file-system $ddump/pages-*.img
		fi

	done

	echo Check results $PID
	if ! stop_test $tdir $tname; then
		echo "Unable to stop $tname ($PID)"
		return 2
	fi

	sltime=1
	for i in `seq 200`; do
		kill -0 $PID > /dev/null 2>&1 || break
		echo Waiting...
		sleep 0.$sltime
		[ $sltime -lt 9 ] && sltime=$((sltime+1))
	done

	if [ -x "${test}.hook" ]; then
		echo "Executing cleanup hook"
		"${test}.hook" --clean
	fi

	if [ -n "$AUTO_DEDUP" ]; then
		for img in $ddump/pages-*.img; do
			img_name="${img##*/}"
			size=$(du -sh -BK "$img" | grep -Eo '[0-9]+' | head -1)
			echo "Size of $img_name is $size"
			if [ "$size" -ne 0 ]; then
				echo "Check: $test, Auto-dedup: image size is more than 0"
				return 2
			fi
		done
	fi

	cat $test.out
	[ $i -gt 50 ] && return 2 # waiting too long
	cat $test.out | grep -q PASS || return 2
	[ "$CLEANUP" -ne 0 ] && rm -rf --one-file-system `dirname $ddump`
	echo "Test: $test, Result: PASS"
	return 0
}

case_error()
{
	local test=${ZP}/${1#ns/}
	local test_log=`pwd`/$test.out

	echo "Test: $test, Result: FAIL"
	ZDTM_FAILED=1

(	exec >&2

	zdtm_sep ERROR

	echo "Test: $test, Namespace: $PIDNS"

	if [ -n "$DUMP_PATH" ]; then
		if [ -e "$DUMP_PATH/dump.log" ]; then
			echo "Dump log   : $DUMP_PATH/dump.log"
			zdtm_sep "grep Error" "-"
			cat $DUMP_PATH/dump.log* | grep Error
			if [ $VERBOSE -gt 0 ]; then
				zdtm_sep "" "-"
				tail -n 40 $DUMP_PATH/dump.log*
			fi
			zdtm_sep "END" "-"
		fi
		if [ -e "$DUMP_PATH/restore.log" ]; then
			echo "Restore log: $DUMP_PATH/restore.log"
			zdtm_sep "grep Error" "-"
			cat $DUMP_PATH/restore.log* | grep Error
			if [ $VERBOSE -gt 0 ]; then
				zdtm_sep "" "-"
				tail -n 40 $DUMP_PATH/restore.log*
			fi
			zdtm_sep "END" "-"
		fi
	fi
	if [ -e "$test_log" ]; then
		echo "Output file: $test_log"
		zdtm_sep "" "-"
		cat $test_log*
		zdtm_sep "END" "-"
	fi

	[ -n "$HEAD" ] &&
		echo "The initial HEAD was $HEAD"

	zdtm_sep "ERROR OVER"
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
	-S : Only start the test
	-n : Batch test
	-r : Run test with specified name directly without match or check
	-f <name>: Run tests starting from @name
	-v : Verbose mode
	-P : Make pre-dump instead of dump on all iterations except the last one
	-s : Make iterative snapshots. Only the last one will be checked.
	--auto-dedup : Make auto-dedup on restore. Check sizes of pages imges, it must be zero.
	--ct : re-execute $0 in a container
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
		if [ -z "$EXCLUDE_PATTERN" ]; then
			EXCLUDE_PATTERN=$1
		else
			EXCLUDE_PATTERN="${EXCLUDE_PATTERN}\|$1"
		fi
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
		if [ -n "$PRE_DUMP" ]; then
			echo "-P and -s can not be used together"
			exit 1
		fi
		SNAPSHOT=1
		shift
		;;
	  -P)
		if [ -n "$SNAPSHOT" ]; then
			echo "-P and -s can not be used together"
			exit 1
		fi
		PRE_DUMP=1
		SNAPSHOT=1
		shift
		;;
	  --auto-dedup)
		AUTO_DEDUP=1
		shift
		;;
	  -g)
		COMPILE_ONLY=1
		shift
		;;
	  -S)
	  	START_ONLY=1
		shift
		;;
	  -f)
	  	shift
	  	START_FROM="^${1}$"
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
		generate_test_list
		echo "$TEST_LIST" >&3
		exit 0
		;;
	  -v)
		VERBOSE=1
		shift
		;;
	  -h)
		usage
		exit 0
		;;
	  --ct)
		[ -z "$ZDTM_SH_IN_CT" ] && {
			export ZDTM_SH_IN_CT=1
			shift
			# pidns is used to avoid conflicts
			# mntns is used to mount /proc
			# net is used to avoid conflicts of parasite sockets
			./zdtm_ct ./zdtm.sh "$@"
			exit
		}
		shift
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
	$CRIU check -v0 --feature "mnt_id" || export ZDTM_NOSUBNS=1
	run_test $1 || case_error $1
else
	if [ $# -eq 0 ]; then
		pattern='.*'
	else
		pattern=$1
	fi

	generate_test_list
	for t in $(echo "$TEST_LIST" | sed -n -e "/${START_FROM////\/}/,\$p" | grep -x "$pattern"); do
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

[ -n "$TMP_TREE" ] && rm -rf --one-file-system $TMP_TREE
[ -n "$ZDTM_FAILED" ] && exit 1 || exit 0
