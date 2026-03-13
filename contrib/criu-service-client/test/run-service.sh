#!/bin/bash
#
# Test pre-dump, dump, and restore via a running criu service daemon.
# The client connects to the service through a Unix socket
# instead of launching criu internally.

set -e

# shellcheck source=contrib/criu-service-client/test/common.sh
. "$(dirname "$0")/common.sh"

IMGS_DIR="${MAIN_DIR}/imgs-service"
SOCKET="${MAIN_DIR}/criu-service.socket"
PIDFILE="${MAIN_DIR}/criu-service.pid"
SERVICE_LOG="${MAIN_DIR}/criu-service.log"

DUMP_DIR="${IMGS_DIR}/dump"

rm -rf "${IMGS_DIR}"
mkdir -p "${DUMP_DIR}"

cleanup() {
	if [ -f "${PIDFILE}" ]; then
		kill "$(cat "${PIDFILE}")" 2>/dev/null || true
		rm -f "${PIDFILE}"
	fi
	rm -f "${SOCKET}"
}
trap cleanup EXIT

# Start the criu service daemon.
criu service --address "${SOCKET}" \
	--log-file "${SERVICE_LOG}" \
	--pidfile "${PIDFILE}" -d -v4

# When criu daemonizes with -d, the parent process can return before
# the daemon has finished writing the pidfile. Poll briefly to give
# it time to appear.
n=0
while [ ! -f "${PIDFILE}" ] && [ $n -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
if [ ! -f "${PIDFILE}" ]; then
	echo "FAIL: criu service did not start"
	exit 1
fi
echo "Service started (PID $(cat "${PIDFILE}"))"

SVC_ADDR="--service-address ${SOCKET}"
LOOP_PID=$("${MAIN_DIR}"/loop)

# Pre-dump requires dirty page tracking which is not available on aarch64.
if criu check --feature mem_dirty_track > /dev/null 2>&1; then
	PRE_DUMP_1="${IMGS_DIR}/pre-dump-1"
	PRE_DUMP_2="${IMGS_DIR}/pre-dump-2"
	mkdir -p "${PRE_DUMP_1}" "${PRE_DUMP_2}"

	# shellcheck disable=SC2086
	${CLIENT} pre-dump \
		-t "${LOOP_PID}" \
		-D "${PRE_DUMP_1}" \
		${SVC_ADDR} \
		--track-mem \
		-v4 \
		-o pre-dump.log
	check_pre_dump "Pre-dump 1 via service" "${PRE_DUMP_1}" "${LOOP_PID}"

	# shellcheck disable=SC2086
	${CLIENT} pre-dump \
		-t "${LOOP_PID}" \
		-D "${PRE_DUMP_2}" \
		${SVC_ADDR} \
		--track-mem \
		-v4 \
		--prev-images-dir ../pre-dump-1 \
		-o pre-dump.log
	check_pre_dump "Pre-dump 2 via service" "${PRE_DUMP_2}" "${LOOP_PID}"

	# shellcheck disable=SC2086
	${CLIENT} dump \
		-t "${LOOP_PID}" \
		-D "${DUMP_DIR}" \
		${SVC_ADDR} \
		--prev-images-dir ../pre-dump-2 \
		--track-mem \
		-v4 \
		-o dump.log
	check_dump "Dump via service" "${DUMP_DIR}" "${LOOP_PID}"
else
	echo "Skipping pre-dump (no mem_dirty_track support)"

	# shellcheck disable=SC2086
	${CLIENT} dump \
		-t "${LOOP_PID}" \
		-D "${DUMP_DIR}" \
		${SVC_ADDR} \
		-v4 \
		-o dump.log
	check_dump "Dump via service" "${DUMP_DIR}" "${LOOP_PID}"
fi

# shellcheck disable=SC2086
do_restore "${LOOP_PID}" -D "${DUMP_DIR}" ${SVC_ADDR} -v4 -o restore.log
