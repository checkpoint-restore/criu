# Wait while tasks are dying, otherwise PIDs would be busy.

function wait_tasks()
{
	local dump=$1
	local pid

	for i in $dump/core-*.img; do
		pid=`expr "$i" : '.*/core-\([0-9]*\).img'`
		while :; do
			kill -0 $pid > /dev/null 2>&1 || break;
			echo Waiting the process $pid
			sleep 0.1
		done
	done
}
