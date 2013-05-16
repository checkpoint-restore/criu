#!/bin/bash

set -x

PORT=12345
CLN_PIPE="./clnt_pipe"
SRV_LOG="./srv.log"
CLN_LOG="./cln.log"
DDIR="dump"
CRTOOLS="../../crtools"

TEXT=$(hexdump -C /dev/urandom | head -n 1)

echo "Building services"

make clean && make || { echo "Failed to build"; exit 1; }
rm -rf ${DDIR} ${SRV_LOG} ${CLN_LOG} ${CLN_PIPE}
mkdir ${DDIR}

echo "Starting server"

setsid ./srv ${PORT} > ${SRV_LOG} 2>&1 &
SRV_PID=${!}

echo "Starting pipe"
mkfifo ${CLN_PIPE}

echo "Starting client"
./cln "127.0.0.1" ${PORT} < ${CLN_PIPE} > ${CLN_LOG} &
CLN_PID=${!}

exec 3>${CLN_PIPE}
echo "Make it run"
echo "${TEXT}" >&3

function fail {
	echo "$@"
	kill -9 ${CLN_PID}
	kill -9 ${SRV_PID}
	exit 1
}

echo "Suspend server"
${CRTOOLS} dump -D ${DDIR} -o dump.log -t ${SRV_PID} --tcp-established -vvvv || fail "Fail to dump server"
sleep 1
echo "Resume server"
${CRTOOLS} restore -D ${DDIR} -o restore.log -d --tcp-established -vvvv --close 3 || fail "Fail to restore server"

echo "Make client run again"
echo "${TEXT}" >&3

echo "Collect results"
exec 3>&-
wait ${CLN_PID}
kill -9 ${SRV_PID}
