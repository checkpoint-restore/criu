
CRIU=./criu/criu

set -x

setsid stress-ng --vm 1 --vm-bytes 10G --vm-keep --vm-hang 0 --timeout 0 </dev/null >&/dev/null &

pid=$(pgrep -n stress-ng)
sudo rm -f ~/.cache/criu/*

sleep 10

sudo $CRIU dump --display-stats -t $pid  -D  ~/.cache/criu --ext-unix-sk

sudo time $CRIU restore --display-stats  -D  ~/.cache/criu --ext-unix-sk --restore-detached || true

sleep 5
kill $pid

sudo rm -f ~/.cache/criu/*

setsid stress-ng --vm 1 --vm-bytes 10G --vm-keep --vm-hang 0 --timeout 0 </dev/null >&/dev/null &

pid=$(pgrep -n stress-ng)
sudo rm -f ~/.cache/criu/*

sleep 10

sudo $CRIU dump --display-stats -t $pid  -D  ~/.cache/criu --ext-unix-sk
sudo time /usr/local/sbin/criu restore --display-stats  -D  ~/.cache/criu --ext-unix-sk --restore-detached || true
sleep 5
kill $pid

echo $?

