#!/bin/bash

set -x

PID=

function run_as {
	echo "== Run ${LOOP} as $1"
	echo ${PIDFILE}
	rm -f ${PIDFILE}
	su $1 -c "setsid ${LOOP} ${PIDFILE} $2 < /dev/null &> /dev/null &"
	for i in `seq 100`; do
		test -f ${PIDFILE} && break
		sleep 1
	done
	PID=`cat ${PIDFILE}`
	echo ${PID}
}

function dump_as {
	test -d ${IMGS} && rm -rf ${IMGS}
	mkdir -p ${IMGS}
	echo "== Dump ${PID} as $@"
	su $@ -c "${CRIU} dump --tree ${PID} --images-dir ${IMGS}"
	return $?
}

function rstr_as {
	echo "== Restore ${IMGS} as $@"
	su $@ -c "${CRIU} restore --images-dir ${IMGS} --restore-detached"
	return $?
}

function result {
	local BGRED='\033[41m'
	local BGGREEN='\033[42m'
	local NORMAL=$(tput sgr0)

	if [ $1 -ne 0 ]; then
		echo -e "${BGRED}FAIL${NORMAL}"
		exit 1
	else
		echo -e "${BGGREEN}PASS${NORMAL}"
	fi
}

function test_root {
	echo "==== Check that non-root can't dump/restore process owned by root"

	run_as  ${ROOT}

	dump_as ${USR1} ; result $((!$?))
	dump_as ${ROOT} ; result $(($?))

	rstr_as ${USR1} ; result $((!$?))
	rstr_as ${ROOT} ; result $(($?))

	kill -SIGKILL ${PID}
}

function test_other {
	echo "==== Check that user2 can't dump/restore process owned by user1"

	run_as  ${USR1}

	dump_as ${USR2} ; result $((!$?))
	dump_as ${USR1} ; result $(($?))

	rstr_as ${USR2} ; result $((!$?))
	rstr_as ${USR1} ; result $(($?))

	kill -SIGKILL ${PID}
}

function test_own {
	echo "==== Check that user1 can dump/restore his own process that changes it's gid to one from groups"

	run_as  ${USR1} "--chgrp"

	dump_as ${USR1} ; result $(($?))

	rstr_as ${USR1} ; result $(($?))

	kill -SIGKILL ${PID}
}

test_root
test_other
test_own
