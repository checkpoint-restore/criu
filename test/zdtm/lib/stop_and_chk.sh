#!/bin/bash

export PATH=$PATH:${0%/*}

function die() {
	echo "ERR: $*"
	exit 1
}

tmpargs="$(parseargs.sh --name=$0 --flags-req=pidfile,outfile -- "$@")" ||
	die "can't parse command line"
eval "$tmpargs"

# check that pidfile exists
if [ ! -r "$pidfile" ]; then
	# if the testcase has written out the outfile, print it
	if [ -r "$outfile" ]; then
		echo $(< "$outfile")
		exit 1
	else
		die "pidfile $pidfile doesn't exist"
	fi
fi

# try to stop the testcase
kill -TERM $(< $pidfile)

# wait at most this many sec for the testcase to stop and wipe out the pidfile
declare -i loops=10
while [ -f "$pidfile" ]; do
	((loops--)) || die "$pidfile still exists"
	sleep 1
done

# see if the testcase has written out the result file
[ -f "$outfile" ] || die "$outfile doesn't exist"

# read in the result
res="$(< "$outfile")"

# dump it to stdout, with the return code reflecting the status
case "$res" in
	PASS)
		echo "$res"
		exit 0
		;;
	FAIL:* | ERR:*)
		echo "$res"
		exit 1
		;;
	*)
		die "$outfile is incomprehensible"
		;;
esac
