#!/bin/bash

set -ex

if [ -e /etc/os-release ]; then
	. /etc/os-release
	if [ "$ID" == "centos" ] && [[ "$VERSION_ID" == "7"* ]];then
		echo "Skipping tests on CentOS 7 because they do not work in CI"
		exit 0
	fi
fi

CRIU=./criu

export PROTODIR=`readlink -f "${PWD}/../../protobuf"`

echo $PROTODIR

function title_print {
	echo -e "\n**************************************************"
	echo -e "\t\t"$1
	echo -e "**************************************************\n"

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

	title_print "Run loop process"
	P=$(../loop)
	echo "pid ${P}"

	title_print "Dump loop process"
	# So theoretically '-j' (--shell-job) should not be necessary, but on alpine
	# this test fails without it.
	${CRIU} dump -j -v4 -o dump-loop.log -D build/imgs_loop -t ${P}

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

test_c
test_py
test_restore_loop
test_ps
test_errno

stop_server

trap 'echo "Success"' EXIT
