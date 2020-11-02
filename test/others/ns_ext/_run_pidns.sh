#!/bin/bash

set -e

status_fd=$1

# Note that with this block we only guaranty that pid of
# __run_pidns.sh would be somewhere around 1000, not
# exactly 1000.

mkdir -p pidns_proc
mount -t proc proc pidns_proc
echo 1000 > pidns_proc/sys/kernel/ns_last_pid
umount -l pidns_proc
rmdir pidns_proc

# Here we create a pipe to wait for __run_pidns.sh to die,
# when it dies the pipe_w is closed and read from pipe_r
# is unblocked.

exec {pipe}<> <(:)
exec {pipe_r}</proc/self/fd/$pipe
exec {pipe_w}>/proc/self/fd/$pipe
exec {pipe}>&-

setsid bash __run_pidns.sh $status_fd &
exec {pipe_w}>&-
exec {status_fd}>&-

# Waiting for __run_pidns.sh to be checkpointed

cat <&$pipe_r
echo "Temporary pidns init is exiting..."
