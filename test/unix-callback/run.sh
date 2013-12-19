#!/bin/bash

cd `dirname $0`

source ../env.sh || exit 1

rm -rf /tmp/criu.unix.callback.test*
test -f pid && unlink pid
test -f output && unlink output
rm -rf data
mkdir -p data

./unix-server &
srv_pid=$!

for i in `seq 20`; do
	test -f /tmp/criu.unix.callback.test && break
	sleep 0.1
done

( setsid ./unix-client < /dev/null &> output ) &

while :; do
	test -f pid && break
	sleep 1
done

pid=`cat pid`

${CRIU} dump --shell-job -D data -o dump.log -v4 --lib `pwd`/lib -t $pid || exit 1
kill $srv_pid
wait $srv_pid
unlink /tmp/criu.unix.callback.test
./unix-server &
srv_pid=$!
for i in `seq 20`; do
	test -f /tmp/criu.unix.callback.test && break
	sleep 0.1
done
${CRIU} restore --shell-job -D data -o restore.log -v4 --lib `pwd`/lib -d || exit 1
kill $pid
while :; do
	cat output | grep PASS && break
	sleep 1
done

cat output
kill $srv_pid
