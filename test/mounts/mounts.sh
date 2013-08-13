[ -z "$INMNTNS" ] && {
	export INMNTNS=`pwd`
	export INMNTNS_PID=$$
	unshare -m -- setsid bash -x "$0" "$@" < /dev/null &> mounts.log &
	echo $! > mounts.pid
	while :; do
		sleep 1
	done
}

cd $INMNTNS

mount --make-rprivate /

for i in `cat /proc/self/mounts | awk '{ print $2 }'`; do
	[ '/' = "$i" ] && continue
	[ '/proc' = "$i" ] && continue
	[ '/dev' = "$i" ] && continue
	echo $i
	umount -l $i
done

python mounts.py
kill $INMNTNS_PID
while :; do
	sleep 10
done
