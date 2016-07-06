#!/bin/sh
set -e -x

# construct root
python ../../zdtm.py run -t zdtm/static/env00 --iter 0 -f ns

truncate -s 0 zdtm.loop
truncate -s 50M zdtm.loop
mkfs.ext4 -F zdtm.loop
dev=`losetup --find --show zdtm.loop`
mkdir -p ../../dev
cp -ap $dev ../../dev
export ZDTM_MNT_EXT_DEV=$dev
python ../../zdtm.py run -t zdtm/static/mnt_ext_dev || ret=$?
losetup -d $dev
unlink zdtm.loop
exit $ret
