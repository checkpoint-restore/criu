#!/bin/bash

set -e

status_fd=$1

exec 0</dev/null
exec 2>/dev/null
exec 1>/dev/null

# Sending our real pid to run_pidns.sh over pipe

exec {fd}</proc/self/status
pid=$(cat <&$fd | grep '^Pid:' | awk '{print $2}')
exec {fd}>&-
echo $pid >&$status_fd
exec {status_fd}>&-

while :; do
	sleep 10000
done
