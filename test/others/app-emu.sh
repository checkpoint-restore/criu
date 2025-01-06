#!/bin/sh

TEST_LIST="
vnc
java/HelloWorld
screen
tarbz
make
"

[ -n "$1" ] && TEST_LIST="$1"

BASE_DIR=`pwd`/`dirname $0`

for t in $TEST_LIST; do
	dir=$BASE_DIR/app-emu/$t
	log=$dir/run.log
	(
		cd $dir
		bash ./run.sh
	) 2>&1 | tee $log
	grep PASS $log || {
		echo "Test: $t"
		echo "====================== ERROR ======================"
		echo "Run log   : $log"
		echo "$t "
		exit 1
	}
done
