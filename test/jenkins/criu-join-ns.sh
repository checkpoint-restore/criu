# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
mkdir -p /var/run/netns
mount -t tmpfs zdtm_run /var/run/netns
./test/zdtm.py run --all --keep-going --report report --join-ns || fail
