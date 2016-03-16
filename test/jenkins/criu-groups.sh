# Make one regular C/R cycle over randomly-generated groups
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump
./test/zdtm.py group --max 32 -x maps04 -x cgroup || fail
./test/zdtm.py --set groups run --all --keep-going --report report -f best || fail
