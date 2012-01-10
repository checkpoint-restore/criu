#!/bin/bash

TEST_LIST="\
zdtm/live/static/pipe00
zdtm/live/static/busyloop00
zdtm/live/static/cwd00
zdtm/live/static/env00
zdtm/live/static/shm
zdtm/live/static/maps00
zdtm/live/static/mprotect00
zdtm/live/static/mtime_mmap
zdtm/live/static/sleeping00
zdtm/live/static/write_read00
zdtm/live/static/write_read01
zdtm/live/static/write_read02
zdtm/live/static/wait00
zdtm/live/static/file_shared
zdtm/live/streaming/pipe_loop00
zdtm/live/streaming/pipe_shared00
zdtm/live/transition/file_read"

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
	mkdir -p $ddump
	setsid $CRTOOLS -D $ddump -o dump.log -d -t $pid || return 1
	while :; do
		killall -9 $tname &> /dev/null || break;
		echo Waiting...
		sleep 1
	done
	setsid $CRTOOLS -D $ddump -o restore.log -r -t $pid &
	sleep 1
	make -C $tdir $tname.out
	wait || return 1
	for i in `seq 5`; do
		test -f $test.out && break;
		echo Waiting...
		sleep 1
	done
	cat $test.out
	cat $test.out | grep PASS || return 1
}

if [ $# -eq 0 ]; then
	cd `dirname $0` || exit 1
	for t in $TEST_LIST; do
		run_test $t || exit 1
	done
else
	run_test $@
fi
