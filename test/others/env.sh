#!/bin/sh

CRIU=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../criu/criu)
criu=$CRIU
CRIT=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../crit/crit)
crit=$CRIT
CRIU_COREDUMP=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../criu-coredump/criu-coredump)
criu_coredump=$CRIU_COREDUMP
