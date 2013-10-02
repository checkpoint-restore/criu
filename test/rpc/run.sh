#!/bin/bash

source ../env.sh || exit 1

export PROTODIR=`readlink -f "${PWD}/../../protobuf"`

echo $PROTODIR

function title_print {
	echo -e "\n**************************************************"
	echo -e "\t\t"$1
	echo -e "**************************************************\n"

}

function _exit {
	if [ $1 -ne 0 ]; then
		echo "FAIL"
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
make -f ../Makefile || { echo "FAIL"; exit 1; }

title_print "Start service server"
${CRIU} service -v4 -o service.log --address criu_service.socket -d --pidfile pidfile || { echo "FAIL"; exit 1; }

title_print "Run test-c"
./test-c || _exit $?

title_print "Run test-py"
../test.py || _exit $?

title_print "Restore test-c"
${CRIU} restore -v4 -o restore-c.log -D imgs_c --shell-job || _exit $?

title_print "Restore test-py"
${CRIU} restore -v4 -o restore-py.log -D imgs_py --shell-job || _exit $?

title_print "Run loop.sh"
setsid ../loop.sh < /dev/null &> loop.log &
P=${!}
echo "pid ${P}"

title_print "Dump loop.sh"
mkdir imgs_loop
${CRIU} dump -v4 -o dump-loop.log -D imgs_loop -t ${P} || _exit $?

title_print "Run restore-loop"
../restore-loop.py || _exit $?
kill -SIGTERM ${P}

_exit 0
