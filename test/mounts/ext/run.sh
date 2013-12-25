#!/bin/bash

set -x

function fail {
	echo $@
	exit 1
}

make || fail "Can't compile library"

criu="../../../criu"

finf="finish"
outf="run_output"
pidfile="pid_wait"
tempd="temp_dir"
sfile="source_file"
tdir="test_dir"
dfile="dest_file"
mesg="msg-$((RANDOM % 128))"
export finf
export outf
export pidfile
export sfile
export dfile
export tempd
export mesg
export tdir

mkdir dump/
mkdir $tdir
mount --bind "/" ${tdir} || fail "Can't bind root"
mount --make-rprivate "${tdir}"

unshare --mount ./run_ns.sh || fail "Can't unshare ns"
cat $pidfile

sleep 2
$criu dump -t $(cat $pidfile) -D dump/ -o dump.log -v4 --lib $(pwd) && echo OK
sleep 1

mkdir $tempd
mount -t tmpfs none "$tempd"
echo "$mesg" > "$tempd/$sfile"
sfpath="/$(pwd)/$tempd/$sfile"
export sfpath

$criu restore -D dump/ -o restore.log -v4 --lib $(pwd) --root "$(pwd)/$tdir" -d && echo OK

umount "$tempd"

touch $finf
sleep 1 # Shitty, but...
tail $outf

umount ${tdir}
