#!/bin/bash

CRIU=../../../criu/criu

set -e -m -x

cat < /dev/zero > /dev/null &
pid=$!
sleep 1
lsof -p $pid

$CRIU exec -t $pid fake_syscall && exit 1 || true
fd=`$CRIU exec -t $pid open '&/dev/null' 0 | sed 's/.*(\(.*\))/\1/'`
$CRIU exec -t $pid dup2 $fd 0
wait $pid
echo PASS
