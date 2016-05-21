source ../env.sh

images_list=""

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
	for x in $images_list
	do
		echo "=== $x"
		if [[ $x == pages* ]]; then
			echo "skip"
			continue
		fi

		echo "  -- to json"
		$CRIT decode -o "$x"".json" --pretty < $x || _exit $?
		echo "  -- to img"
		$CRIT encode -i "$x"".json" > "$x"".json.img" || _exit $?
		echo "  -- cmp"
		cmp $x "$x"".json.img" || _exit $?

		echo "=== done"
	done
}

gen_imgs
run_test
