#!/bin/bash

set -e

CRIU=./criu

export PROTODIR=`readlink -f "${PWD}/../../protobuf"`

echo $PROTODIR

function title_print {
	echo -e "\n**************************************************"
	echo -e "\t\t"$1
	echo -e "**************************************************\n"

}

function start_server {
	title_print "Start service server"
	${CRIU} service -v4 -W build -o service.log --address criu_service.socket -d --pidfile pidfile
}

function stop_server {
	title_print "Shutdown service server"
	kill -SIGTERM $(cat build/pidfile)
	unlink build/pidfile
}

function test_c {
	mkdir -p build/imgs_c

	title_print "Run test-c"
	setsid ./test-c build/criu_service.socket build/imgs_c < /dev/null &>> build/output_c

	title_print "Restore test-c"
	${CRIU} restore -v4 -o restore-c.log -D build/imgs_c
}

function test_py {
	mkdir -p build/imgs_py

	title_print "Run test-py"
	setsid ./test.py build/criu_service.socket build/imgs_py < /dev/null &>> build/output_py

	title_print "Restore test-py"
	${CRIU} restore -v4 -o restore-py.log -D build/imgs_py
}

function test_restore_loop {
	mkdir -p build/imgs_loop

	title_print "Run loop.sh"
	setsid ./loop.sh < /dev/null &> build/loop.log &
	P=${!}
	echo "pid ${P}"

	title_print "Dump loop.sh"
	${CRIU} dump -v4 -o dump-loop.log -D build/imgs_loop -t ${P}

	title_print "Run restore-loop"
	./restore-loop.py build/criu_service.socket build/imgs_loop
	kill -SIGTERM ${P}
}

function test_ps {
	mkdir -p build/imgs_ps

	title_print "Run ps_test"
	setsid ./ps_test.py build/criu_service.socket build/imgs_ps < /dev/null &>> build/output_ps
}

function test_errno {
	mkdir -p build/imgs_errno

	title_print "Run cr_errno test"
	setsid ./errno.py build/criu_service.socket build/imgs_errno < /dev/null &>> build/output_errno
}

trap 'echo "FAIL"; stop_server' EXIT

start_server

test_c
test_py
test_restore_loop
test_ps
test_errno

stop_server

trap 'echo "Success"' EXIT
