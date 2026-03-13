#!/bin/bash
#
# Test iterative pre-dump, dump, and restore using a loop workload.

set -e

# shellcheck source=contrib/criu-service-client/test/common.sh
. "$(dirname "$0")/common.sh"

IMGS_DIR="${MAIN_DIR}/imgs"
DUMP_DIR="${IMGS_DIR}/dump"

rm -rf "${IMGS_DIR}"

LOOP_PID=$("${MAIN_DIR}"/loop)

# Pre-dump requires dirty page tracking which is not available on aarch64.
if criu check --feature mem_dirty_track > /dev/null 2>&1; then
	PRE_DUMP_1="${IMGS_DIR}/pre-dump-1"
	PRE_DUMP_2="${IMGS_DIR}/pre-dump-2"
	mkdir -p "${PRE_DUMP_1}" "${PRE_DUMP_2}" "${DUMP_DIR}"

	${CLIENT} pre-dump \
		-t "${LOOP_PID}" \
		-D "${PRE_DUMP_1}" \
		--track-mem \
		-v4 \
		-o pre-dump.log
	check_pre_dump "Pre-dump 1" "${PRE_DUMP_1}" "${LOOP_PID}"

	${CLIENT} pre-dump \
		-t "${LOOP_PID}" \
		-D "${PRE_DUMP_2}" \
		--track-mem \
		-v4 \
		--prev-images-dir ../pre-dump-1 \
		-o pre-dump.log
	check_pre_dump "Pre-dump 2" "${PRE_DUMP_2}" "${LOOP_PID}"

	${CLIENT} dump \
		-t "${LOOP_PID}" \
		-D "${DUMP_DIR}" \
		--prev-images-dir ../pre-dump-2 \
		--track-mem \
		-v4 \
		-o dump.log
	check_dump "Dump" "${DUMP_DIR}" "${LOOP_PID}"
else
	echo "Skipping pre-dump (no mem_dirty_track support)"
	mkdir -p "${DUMP_DIR}"

	${CLIENT} dump \
		-t "${LOOP_PID}" \
		-D "${DUMP_DIR}" \
		-v4 \
		-o dump.log
	check_dump "Dump" "${DUMP_DIR}" "${LOOP_PID}"
fi

do_restore "${LOOP_PID}" -D "${DUMP_DIR}" -v4 -o restore.log
