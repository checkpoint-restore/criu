# Test how freeze cgroup works
set -e
source `dirname $0`/criu-lib.sh
prep
mount_tmpfs_to_dump

./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:f || fail
./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:f --pre 3 || fail
./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:f --norst || fail

./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:t || fail
./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:t --pre 3 || fail
./test/zdtm.py run -t zdtm/transition/thread-bomb -f h --report report --freezecg zdtm:t --norst || fail
