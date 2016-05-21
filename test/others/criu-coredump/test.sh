source ../env.sh

function _exit {
	if [ $? -ne 0 ]; then
		echo "FAIL"
		exit 1
	fi
}

function gen_imgs {
	setsid ./loop.sh < /dev/null &> /dev/null &
	PID=$!
	$CRIU dump -v4 -o dump.log -D ./ -t $PID
	if [ $? -ne 0 ]; then
		kill -9 $PID
		_exit 1
	fi

	images_list=$(ls -1 *.img)
	if [ -z "$images_list" ]; then
		echo "Failed to generate images"
		_exit 1
	fi
}

function run_test {
	echo "= Test core dump"

	echo "=== img to core dump"
	$CRIU_COREDUMP -i ./ -o ./ || _exit $?
	echo "=== done"

	cores=$(ls -1 core.*)
	if [ -z "$cores" ]; then
		echo "Failed to generate coredumps"
		_exit 1
	fi

	for x in $cores
	do
		echo "=== try readelf $x"
		readelf -a $x || _exit $?
		echo "=== done"
	done

	echo "= done"
}

gen_imgs
run_test
