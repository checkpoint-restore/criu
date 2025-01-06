#!/bin/bash
#set -x
set -m
Xvnc :25 -v -geometry 500x500 -i 0.0.0.0 -SecurityTypes none &
pid=$!
trap "kill $pid; wait" EXIT
for i in `seq 10`; do
	nc -w 1 localhost 5925 | grep -am 1 RFB && break || echo Waiting
	kill -0 $pid || exit 1
	sleep 1
done
kill -STOP $$
DISPLAY=:25 glxgears
