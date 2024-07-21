#!/bin/sh
set -e -x

# construct root
python3 ../../zdtm.py run -t zdtm/static/env00 --iter 0 -f ns

truncate -s 0 zdtm.loop
truncate -s 50M zdtm.loop
mkfs.ext4 -F zdtm.loop
dev=`losetup --find --show zdtm.loop`
export ZDTM_MNT_EXT_DEV=$dev
python3 ../../zdtm.py run $EXTRA_OPTS -t zdtm/static/mnt_ext_dev || ret=$?
losetup -d $dev
unlink zdtm.loop
exit $ret
