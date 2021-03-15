#!/bin/bash
# shellcheck disable=SC1091,SC2002

set -x

source ../env.sh

images_list=""

function _exit {
	# shellcheck disable=SC2181
	if [ $? -ne 0 ]; then
		echo "FAIL"
		exit 1
	fi
}

function gen_imgs {
	setsid ./loop.sh < /dev/null &> /dev/null &
	PID=$!
	$CRIU dump -v4 -o dump.log -D ./ -t $PID
	# shellcheck disable=SC2181
	if [ $? -ne 0 ]; then
		kill -9 $PID
		_exit 1
	fi

	images_list=$(ls -1 ./*.img)
	if [ -z "$images_list" ]; then
		echo "Failed to generate images"
		_exit 1
	fi
}

function run_test1 {
	for x in $images_list
	do
		echo "=== $x"
		if [[ $x == *pages* ]]; then
			echo "skip"
			continue
		fi

		echo "  -- to json"
		$CRIT decode -o "$x"".json" --pretty < "$x" || _exit $?
		echo "  -- to img"
		$CRIT encode -i "$x"".json" > "$x"".json.img" || _exit $?
		echo "  -- cmp"
		cmp "$x" "$x"".json.img" || _exit $?

		echo "=== done"
	done
}


function run_test2 {
	mapfile -t array <<< "$images_list"

	PROTO_IN=${array[0]}
	JSON_IN=$(mktemp -p ./ tmp.XXXXXXXXXX.json)
	OUT=$(mktemp -p ./ tmp.XXXXXXXXXX.log)

	# prepare
	${CRIT} decode -i "${PROTO_IN}" -o "${JSON_IN}"

	# proto in - json out decode
	cat "${PROTO_IN}" | ${CRIT} decode || _exit 1
	cat "${PROTO_IN}" | ${CRIT} decode -o "${OUT}" || _exit 1
	cat "${PROTO_IN}" | ${CRIT} decode > "${OUT}" || _exit 1
	${CRIT} decode -i "${PROTO_IN}" || _exit 1
	${CRIT} decode -i "${PROTO_IN}" -o "${OUT}" || _exit 1
	${CRIT} decode -i "${PROTO_IN}" > "${OUT}" || _exit 1
	${CRIT} decode < "${PROTO_IN}" || _exit 1
	${CRIT} decode -o "${OUT}" < "${PROTO_IN}" || _exit 1
	${CRIT} decode < "${PROTO_IN}" > "${OUT}" || _exit 1

	# proto in - json out encode -> should fail
	cat "${PROTO_IN}" | ${CRIT} encode || true
	cat "${PROTO_IN}" | ${CRIT} encode -o "${OUT}" || true
	cat "${PROTO_IN}" | ${CRIT} encode > "${OUT}" || true
	${CRIT} encode -i "${PROTO_IN}" || true
	${CRIT} encode -i "${PROTO_IN}" -o "${OUT}" || true
	${CRIT} encode -i "${PROTO_IN}" > "${OUT}" || true

	# json in - proto out encode
	cat "${JSON_IN}" | ${CRIT} encode || _exit 1
	cat "${JSON_IN}" | ${CRIT} encode -o "${OUT}" || _exit 1
	cat "${JSON_IN}" | ${CRIT} encode > "${OUT}" || _exit 1
	${CRIT} encode -i "${JSON_IN}" || _exit 1
	${CRIT} encode -i "${JSON_IN}" -o "${OUT}" || _exit 1
	${CRIT} encode -i "${JSON_IN}" > "${OUT}" || _exit 1
	${CRIT} encode < "${JSON_IN}" || _exit 1
	${CRIT} encode -o "${OUT}" < "${JSON_IN}" || _exit 1
	${CRIT} encode < "${JSON_IN}" > "${OUT}" || _exit 1

	# json in - proto out decode -> should fail
	cat "${JSON_IN}" | ${CRIT} decode || true
	cat "${JSON_IN}" | ${CRIT} decode -o "${OUT}" || true
	cat "${JSON_IN}" | ${CRIT} decode > "${OUT}" || true
	${CRIT} decode -i "${JSON_IN}" || true
	${CRIT} decode -i "${JSON_IN}" -o "${OUT}" || true
	${CRIT} decode -i "${JSON_IN}" > "${OUT}" || true
}

gen_imgs
run_test1
run_test2
