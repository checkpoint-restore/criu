#!/bin/bash

# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run -t zdtm/static/env00 --fault 1 --report report -f h || fail
./test/zdtm.py run -t zdtm/static/unlink_fstat00 --fault 2 --report report -f h || fail
./test/zdtm.py run -t zdtm/static/maps00 --fault 3 --report report -f h || fail

# FIXME: fhandles looks broken on btrfs
grep -P "/.* / " /proc/self/mountinfo | grep -q btrfs || NOBTRFS=$?
if [ $NOBTRFS -eq 1 ] ; then
	./test/zdtm.py run -t zdtm/static/inotify_irmap --fault 128 --pre 2 -f uns || fail
fi

./test/zdtm.py run -t zdtm/static/env00 --fault 129 -f uns || fail
./test/zdtm.py run -t zdtm/transition/fork --fault 130 -f h || fail
./test/zdtm.py run -t zdtm/static/vdso01 --fault 127 || fail
./test/zdtm.py run -t zdtm/static/vdso-proxy --fault 127 --iters 3 || fail

if [ "${COMPAT_TEST}" != "y" ] ; then
	./test/zdtm.py run -t zdtm/static/vdso01 --fault 133 -f h || fail
fi

./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 2 --report report || fail
./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 4 --report report || fail

./test/zdtm.py run -t zdtm/static/mntns_ghost --fault 6 --report report || fail
./test/zdtm.py run -t zdtm/static/mntns_link_remap --fault 6 --report report || fail
./test/zdtm.py run -t zdtm/static/unlink_fstat03 --fault 6 --report report || fail

./test/zdtm.py run -t zdtm/static/env00 --fault 5 --report report || fail
./test/zdtm.py run -t zdtm/static/maps04 --fault 131 --report report --pre 2:1 || fail
./test/zdtm.py run -t zdtm/transition/maps008 --fault 131 --report report --pre 2:1 || fail
./test/zdtm.py run -t zdtm/static/maps01 --fault 132 -f h || fail
# 134 is corrupting extended registers set, should run in a sub-thread (fpu03)
# without restore (that will check if parasite corrupts extended registers)
./test/zdtm.py run -t zdtm/static/fpu03 --fault 134 -f h --norst || fail
# also check for the main thread corruption
./test/zdtm.py run -t zdtm/static/fpu00 --fault 134 -f h --norst || fail
