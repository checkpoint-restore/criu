set -m

source ../../functions.sh || exit 1

crtools="../../../crtools"

mkdir data

./vnc-server.sh 25 &> data/vnc.log
pid=`jobs -p %1`
bg

$crtools dump -j --tcp-established -D data/ -o dump.log -v 4 -t $pid || {
	echo "Dump failed"
	exit 1
}

wait_tasks dump

$crtools restore -j --tcp-established -D data/ -d -o restore.log -v 4 || {
	echo "Restore failed"
	exit 1
}

nc -w 1 localhost 5925 | grep -am 1 RFB
ret=$?

kill $pid

[ "$ret" -eq 0 ] && echo PASS || echo FAIL;

exit $ret
