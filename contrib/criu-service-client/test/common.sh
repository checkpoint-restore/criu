#!/bin/bash
#
# Shared helpers for the criu-service-client tests.
# Source this file; do not run it directly.

MAIN_DIR=$(dirname "$0")
CLIENT="${MAIN_DIR}/../criu-service-client"

make -s -C "${MAIN_DIR}/.." criu-service-client
make -s -C "${MAIN_DIR}"

# When LOCAL=1 (default), use libcriu and criu from the source tree.
if [ "${LOCAL:-1}" = "1" ]; then
	export LD_LIBRARY_PATH="${MAIN_DIR}/../.install/lib"
	export PATH="${MAIN_DIR}/../../../criu:${PATH}"
fi

# Dump all CRIU log files on failure to aid debugging.
dump_logs() {
	local rc=$?
	if [ ${rc} -ne 0 ]; then
		echo "--- CRIU log files ---"
		find "${MAIN_DIR}" -name '*.log' -print -exec cat {} \;
		echo "--- end of logs ---"
	fi
	return ${rc}
}
trap dump_logs EXIT

check_pre_dump() {
	local label="$1" imgs_dir="$2" pid="$3"

	if ! kill -0 "${pid}" 2>/dev/null; then
		echo "FAIL: process died after ${label}"
		exit 1
	fi
	if [ ! -f "${imgs_dir}/inventory.img" ]; then
		echo "FAIL: no inventory image after ${label}"
		exit 1
	fi
	echo "${label} passed"
}

check_dump() {
	local label="$1" imgs_dir="$2" pid="$3"

	# The target is orphaned to init, so there is a small window where
	# it remains a zombie (kill -0 still succeeds) after CRIU returns
	# but before init cleans it up. Wait via pidfd_open(2) for up to 5s.
	if ! "${MAIN_DIR}/pidfd-wait.py" "${pid}" 5; then
		echo "FAIL: process still alive after ${label}"
		kill -SIGKILL "${pid}"
		exit 1
	fi
	if [ ! -f "${imgs_dir}/inventory.img" ]; then
		echo "FAIL: no inventory image after ${label}"
		exit 1
	fi
	echo "${label} passed"
}

# Restore in the background and wait for the process to reappear.
# The client blocks in criu_restore_child() + waitpid() until the
# restored process exits, so we run it in the background.  Stdin is
# redirected from /dev/null so the client does not try to take over
# the terminal.
do_restore() {
	local pid="$1"
	shift

	${CLIENT} restore "$@" < /dev/null &
	local client_pid=$!

	# shellcheck disable=SC2016
	timeout 10 sh -c 'while ! kill -0 "$1" 2>/dev/null; do sleep 0.1; done' -- "${pid}"

	if ! kill -0 "${pid}" 2>/dev/null; then
		echo "FAIL: process not running after restore"
		exit 1
	fi

	kill -SIGKILL "${pid}"

	# The client exits with 128+SIGKILL=137 (the loop's exit status).
	wait ${client_pid} || test $? -eq 137

	echo "Restore passed"
}
