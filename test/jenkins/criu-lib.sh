function exit_hook()
{
	test -z "$GCOV" && return
	make gcov
}

function prep()
{
	test -n "$SKIP_PREP" && return
	# systemd executes jenkins in a separate sched cgroup.
	echo 950000 > /sys/fs/cgroup/cpu,cpuacct/system/cpu.rt_runtime_us || true
	echo 950000 > /sys/fs/cgroup/cpu,cpuacct/system/jenkins.service/cpu.rt_runtime_us || true

	test -n "$GCOV" && umask 0000

	ulimit -c unlimited &&
	export CFLAGS=-g
	git clean -dfx &&
	make -j 4 &&
	make -j 4 -C test/zdtm/ &&
	make -C test zdtm_ct &&
	mkdir -p test/report &&
	trap exit_hook EXIT
}

function mount_tmpfs_to_dump()
{
	test -n "$SKIP_PREP" && return	
	mkdir -p test/dump &&
	mount -t tmpfs criu_dump test/dump &&
	true
}

function fail()
{
	set +e
	uname -a
	ps axf --width 256 > ps.log
	tar -czf /home/`basename $0`-${BUILD_NUMBER}-${GIT_COMMIT}-$(date +%m%d%H%M).tar.gz .
	tar -czf report.tar.gz -C test/ report
	exit 1
}
