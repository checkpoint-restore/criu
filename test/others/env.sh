#!/bin/sh

CRIU=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../criu/criu)
criu=$CRIU
if [ $(which python3) ]; then
	PYTHON=python3
elif [ $(which python2) ]; then
	PYTHON=python2
else
	echo "FAIL: Neither python3 nor python2"
	exit 1
fi
#export PYTHON
CRIT=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../crit/crit-"${PYTHON}")
crit=$CRIT
CRIU_COREDUMP=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../coredump/coredump-"${PYTHON}")
criu_coredump=$CRIU_COREDUMP
