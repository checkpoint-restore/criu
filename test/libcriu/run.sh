#!/bin/bash

source ../env.sh || exit 1

export PROTODIR=`readlink -f "${PWD}/../../protobuf"`

echo $PROTODIR

LOOP_PID=0

function title_print {
	echo -e "\n**************************************************"
	echo -e "\t\t"$1
	echo -e "**************************************************\n"

}

function _exit {
	if [ $1 -ne 0 ]; then
		echo "FAIL"
	fi

	if [ $LOOP_PID -ne 0 ]; then
		kill -SIGTERM $LOOP_PID
	fi

	title_print "Shutdown service server"
	kill -SIGTERM `cat pidfile`

	exit $1
}

function check_and_term {
	title_print "Check and term $1"
	ps -C $1
	pkill $1
}

title_print "Build programs"
make clean
mkdir build
cd build
mkdir imgs_loop
mkdir imgs_test
make -C ../ || { echo "FAIL"; exit 1; }

title_print "Start service server"
${CRIU} service -v4 -o service.log --address criu_service.socket -d --pidfile `pwd`/pidfile || { echo "FAIL"; exit 1; }

title_print "Run loop.sh"
setsid ../loop.sh < /dev/null &> loop.log &
LOOP_PID=${!}
echo "pid ${LOOP_PID}"

title_print "Run test.c"
LD_LIBRARY_PATH=../../../lib
export LD_LIBRARY_PATH
./test ${LOOP_PID} || _exit $?

title_print "Restore test.c"
${CRIU} restore -v4 -o restore-test.log -D imgs_test --shell-job || _exit $?

_exit 0
