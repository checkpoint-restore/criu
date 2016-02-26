#!/bin/sh

CRIU=$(readlink -f `dirname ${BASH_SOURCE[0]}`/../../criu/criu)
criu=$CRIU
