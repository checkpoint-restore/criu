
CRIU=./criu/criu

set -eux

setsid stress-ng --vm 1 --vm-bytes 10G --vm-keep --vm-hang 0 --timeout 0 </dev/null >&/dev/null &

pid=$(pgrep -n stress-ng)
sudo rm -f ~/.cache/criu/*

sleep 5

sudo $CRIU dump --display-stats -t $pid  -D  ~/.cache/criu --ext-unix-sk

for h in 1 2 4 8; do 
  sudo time $CRIU restore --host-mem-workers $h  --display-stats  -D  ~/.cache/criu --ext-unix-sk --restore-detached || true
  sleep 1
  kill -9 -$pid

  # kill -9 only sends the signal; the detached process is reparented to
  # init and lingers as a zombie (still holding PID $pid) until reaped.
  # Wait for the PID to be fully gone before restoring it again, otherwise
  # clone3(set_tid=$pid) fails with EEXIST ("File exists").
  while kill -0 $pid 2>/dev/null; do sleep 0.2; done
  sleep 5
done

sudo time /usr/local/sbin/criu restore --display-stats  -D  ~/.cache/criu --ext-unix-sk --restore-detached || true
sleep 5
kill $pid

echo $?

