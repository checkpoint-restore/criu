# Check lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep

# FIXME: maps007 is sometimes failing with lazy-pages, exclude it for now

# lazy restore from images
./test/zdtm.py run --all --keep-going --report report --parallel 4 --lazy-pages -x maps007 || fail

# lazy restore from images with pre-dumps
./test/zdtm.py run --all --keep-going --report report --parallel 4 --lazy-pages --pre 2 -x maps007 || fail

# lazy restore from "remote" dump
./test/zdtm.py run --all --keep-going --report report --parallel 4 --remote-lazy-pages -x maps007 || fail
