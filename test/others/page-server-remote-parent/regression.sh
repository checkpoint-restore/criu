#!/bin/bash

set -euo pipefail

# shellcheck source=test/others/env.sh
source ../env.sh

CRIU_CMD=("${CRIU}" --no-default-config)
ZDTM_DIR="../../zdtm/static"
IMAGE_TOOL="./generation_oracle.py"
PRE_DUMP_MODE="${PRE_DUMP_MODE:-splice}"
case "$PRE_DUMP_MODE" in
	splice|read) ;;
	*) echo "Invalid PRE_DUMP_MODE: $PRE_DUMP_MODE" >&2; exit 2 ;;
esac
ORACLE_STATE=""
WORK_DIR="remote-parent-regression.$"
PID=""
PAGE_SERVER_PID=""

fail() {
	echo "FAIL: $*"
	if [ -d "$WORK_DIR" ]; then
		find "$WORK_DIR" -type f -name '*.log' -print -exec sh -c 'echo "--- $1"; tail -n 100 "$1"' _ {} \; || true
	fi
	exit 1
}

cleanup() {
	if [ -n "$PAGE_SERVER_PID" ] && kill -0 "$PAGE_SERVER_PID" 2>/dev/null; then
		kill -TERM "$PAGE_SERVER_PID" 2>/dev/null || true
		wait "$PAGE_SERVER_PID" 2>/dev/null || true
	fi
	PAGE_SERVER_PID=""

	if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
		kill -TERM "$PID" 2>/dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$PID" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$PID" 2>/dev/null; then
			kill -KILL "$PID" 2>/dev/null || true
		fi
	fi
	PID=""
}
trap cleanup EXIT

sum_pages_bytes() {
	local directory="$1"
	local total=0
	local file

	for file in "$directory"/pages-*.img; do
		[ -e "$file" ] || continue
		total=$((total + $(wc -c < "$file")))
	done
	printf '%d\n' "$total"
}

sum_coverage_bytes() {
	local directory="$1"
	local total=0
	local file

	for file in "$directory"/remote-parent-*.img; do
		[ -e "$file" ] || continue
		total=$((total + $(wc -c < "$file")))
	done
	printf '%d\n' "$total"
}

assert_coverage_committed() {
	local directory="$1"

	compgen -G "$directory/remote-parent-*.img" >/dev/null ||
		fail "remote-parent coverage is missing"
	if compgen -G "$directory/.remote-parent-*.tmp.*" >/dev/null; then
		fail "temporary remote-parent coverage was not removed"
	fi
}

free_port() {
	python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_page_server() {
	local port="$1"
	local i

	for i in $(seq 1 100); do
		kill -0 "$PAGE_SERVER_PID" 2>/dev/null ||
			fail "page server exited before accepting a connection"
		if [ -n "$(ss -H -ltn "sport = :$port")" ]; then
			return
		fi
		sleep 0.02
	done
	fail "page server did not start listening"
}

start_page_server() {
	local image_dir="$1"
	local port="$2"

	shift 2
	"${CRIU_CMD[@]}" page-server -D "$image_dir" -o page-server.log -v4 --port "$port" "$@" &
	PAGE_SERVER_PID=$!
	wait_page_server "$port"
}

finish_page_server() {
	local label="$1"

	if ! wait "$PAGE_SERVER_PID"; then
		fail "$label"
	fi
	PAGE_SERVER_PID=""
}

start_test() {
	ORACLE_STATE=""
	(
		cd "$ZDTM_DIR"
		make compress_pages00.cleanout
		make compress_pages00
		"$BASE_PAGE_LAUNCHER" make compress_pages00.pid
	)

	PID=$(cat "$ZDTM_DIR/compress_pages00.pid")
	kill -0 "$PID" 2>/dev/null || fail "workload did not start"
}

stop_test() {
	local label="$1"

	if [ -n "$ORACLE_STATE" ]; then
		run_image_tool verify-and-reset "$PID" "$ORACLE_STATE" ||
			fail "$label: stale or corrupt restored page generation"
	fi

	(
		cd "$ZDTM_DIR"
		make compress_pages00.stop
		grep PASS compress_pages00.out
	) || fail "$label: restored memory verification failed"
	PID=""
}

run_image_tool() {
	PYTHONPATH="${BASE_DIR}/lib${PYTHONPATH:+:${PYTHONPATH}}" \
		python3 "$IMAGE_TOOL" "$@"
}

dirty_page_generation() {
	local image_dir="$1"
	local address_file="$2"

	ORACLE_STATE="$address_file"
	run_image_tool mutate "$image_dir" "$PID" "$ORACLE_STATE"
}

run_local_parent_control() {
	local base="$WORK_DIR/local-control"
	local pre="$base/pre"
	local final="$base/final"
	local pre_bytes
	local final_bytes

	echo "=== local parent control ==="
	mkdir -p "$pre" "$final"
	start_test

	"${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" -D "$pre" -o dump.log -t "$PID" -v4 --track-mem ||
		fail "local control pre-dump failed"
	dirty_page_generation "$pre" "$base/toggle-address" ||
		fail "local control could not dirty workload page"

	"${CRIU_CMD[@]}" dump -D "$final" -o dump.log -t "$PID" -v4 --track-mem \
		--prev-images-dir ../pre ||
		fail "local control final dump failed"

	pre_bytes=$(sum_pages_bytes "$pre")
	run_image_tool check-image "$final" "$PID" "$ORACLE_STATE" ||
		fail "final image has incorrect generation placement"
	final_bytes=$(sum_pages_bytes "$final")
	echo "local-control pre pages bytes:   $pre_bytes"
	echo "local-control final pages bytes: $final_bytes"

	[ "$pre_bytes" -gt $((8 * 1024 * 1024)) ] ||
		fail "local control workload is too small"
	[ "$final_bytes" -gt 0 ] ||
		fail "local control final dump contains no page payload"
	[ $((final_bytes * 4)) -lt "$pre_bytes" ] ||
		fail "local control final dump is not incremental"

	"${CRIU_CMD[@]}" restore -D "$final" -o restore.log -v4 -d ||
		fail "local control restore failed"
	stop_test "local control"

	LOCAL_CONTROL_FINAL_BYTES="$final_bytes"
}

run_remote_parent_regression() {
	local base="$WORK_DIR/remote-parent"
	local source_pre="$base/source-pre"
	local target_pre="$base/target-pre"
	local final="$base/final"
	local port
	local source_pre_bytes
	local coverage_bytes
	local remote_pre_bytes
	local final_bytes

	echo "=== remote page-server parent regression ==="
	mkdir -p "$source_pre" "$target_pre" "$final"
	start_test
	port=$(free_port)
	start_page_server "$target_pre" "$port"

	"${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" -D "$source_pre" -o dump.log -t "$PID" -v4 --track-mem \
		--page-server --address 127.0.0.1 --port "$port" ||
		fail "remote pre-dump failed"
	finish_page_server "page server failed while receiving pre-dump"

	source_pre_bytes=$(sum_pages_bytes "$source_pre")
	coverage_bytes=$(sum_coverage_bytes "$source_pre")
	remote_pre_bytes=$(sum_pages_bytes "$target_pre")
	echo "source-side pre-dump page bytes: $source_pre_bytes"
	echo "source-side coverage bytes:      $coverage_bytes"
	echo "page-server pre-dump page bytes: $remote_pre_bytes"

	[ "$source_pre_bytes" -eq 0 ] ||
		fail "pre-dump retained memory payload on the source"
	[ "$remote_pre_bytes" -gt $((8 * 1024 * 1024)) ] ||
		fail "page server did not receive the expected payload"
	assert_coverage_committed "$source_pre"
	if [ "$coverage_bytes" -le 0 ] || [ $((coverage_bytes * 64)) -ge "$remote_pre_bytes" ]; then
		fail "source-side coverage is not compact"
	fi

	dirty_page_generation "$target_pre" "$base/toggle-address" ||
		fail "remote-parent case could not dirty workload page"

	"${CRIU_CMD[@]}" dump -D "$final" -o dump.log -t "$PID" -v4 --track-mem \
		--prev-images-dir ../source-pre ||
		fail "remote-parent final local dump failed"
	grep -q "Using remote parent coverage" "$final/dump.log" ||
		fail "final dump did not select remote-parent coverage"

	run_image_tool check-image "$final" "$PID" "$ORACLE_STATE" ||
		fail "final image has incorrect generation placement"
	final_bytes=$(sum_pages_bytes "$final")
	echo "remote-parent final pages bytes: $final_bytes"
	[ "$final_bytes" -gt 0 ] ||
		fail "remote-parent final dump contains no dirty-page payload"
	[ "$final_bytes" -le $((LOCAL_CONTROL_FINAL_BYTES * 4)) ] ||
		fail "remote-parent final dump is larger than the local control"
	[ $((final_bytes * 4)) -lt "$remote_pre_bytes" ] ||
		fail "remote-parent final dump fell back toward a full image"

	mkdir -p "$base/target-final"
	cp -a "$final/." "$base/target-final/"
	rm -f "$base/target-final/parent"
	ln -s ../target-pre "$base/target-final/parent"
	"${CRIU_CMD[@]}" restore -D "$base/target-final" -o restore.log -v4 -d ||
		fail "assembled destination image failed to restore"
	stop_test "remote-parent incremental restore"

	REMOTE_PARENT_COVERAGE_BYTES="$coverage_bytes"
	REMOTE_PARENT_FINAL_BYTES="$final_bytes"
	REMOTE_PARENT_PRE_BYTES="$remote_pre_bytes"
}

run_remote_parent_multiround_regression() {
	local base="$WORK_DIR/remote-parent-multiround"
	local source_pre1="$base/source-pre1"
	local source_pre2="$base/source-pre2"
	local target_pre1="$base/target-pre1"
	local target_pre2="$base/target-pre2"
	local final="$base/final"
	local port
	local source_pre1_bytes
	local source_pre2_bytes
	local coverage_pre1_bytes
	local coverage_pre2_bytes
	local target_pre1_bytes
	local target_pre2_bytes
	local final_bytes

	echo "=== chained remote page-server parent regression ==="
	mkdir -p "$source_pre1" "$source_pre2" "$target_pre1" "$target_pre2" "$final"
	start_test

	port=$(free_port)
	start_page_server "$target_pre1" "$port"
	"${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" -D "$source_pre1" -o dump.log -t "$PID" -v4 --track-mem \
		--page-server --address 127.0.0.1 --port "$port" ||
		fail "first remote pre-dump failed"
	finish_page_server "first-round page server failed"

	source_pre1_bytes=$(sum_pages_bytes "$source_pre1")
	coverage_pre1_bytes=$(sum_coverage_bytes "$source_pre1")
	target_pre1_bytes=$(sum_pages_bytes "$target_pre1")
	[ "$source_pre1_bytes" -eq 0 ] ||
		fail "first pre-dump retained memory payload on the source"
	[ "$target_pre1_bytes" -gt $((8 * 1024 * 1024)) ] ||
		fail "first page-server pre-dump is unexpectedly small"
	assert_coverage_committed "$source_pre1"

	dirty_page_generation "$target_pre1" "$base/toggle-address" ||
		fail "could not dirty a page before the second pre-dump"

	port=$(free_port)
	start_page_server "$target_pre2" "$port" --prev-images-dir ../target-pre1
	"${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" -D "$source_pre2" -o dump.log -t "$PID" -v4 --track-mem \
		--prev-images-dir ../source-pre1 \
		--page-server --address 127.0.0.1 --port "$port" ||
		fail "second remote pre-dump failed"
	finish_page_server "second-round page server failed"
	run_image_tool check-image "$target_pre2" "$PID" "$ORACLE_STATE" ||
		fail "second round has incorrect generation placement"

	source_pre2_bytes=$(sum_pages_bytes "$source_pre2")
	coverage_pre2_bytes=$(sum_coverage_bytes "$source_pre2")
	target_pre2_bytes=$(sum_pages_bytes "$target_pre2")
	echo "multiround source pre1 pages:    $source_pre1_bytes"
	echo "multiround source pre1 coverage: $coverage_pre1_bytes"
	echo "multiround target pre1 pages:    $target_pre1_bytes"
	echo "multiround source pre2 pages:    $source_pre2_bytes"
	echo "multiround source pre2 coverage: $coverage_pre2_bytes"
	echo "multiround target pre2 pages:    $target_pre2_bytes"

	[ "$source_pre2_bytes" -eq 0 ] ||
		fail "second pre-dump retained memory payload on the source"
	[ "$target_pre2_bytes" -gt 0 ] ||
		fail "second page-server pre-dump contains no dirty-page payload"
	[ $((target_pre2_bytes * 4)) -lt "$target_pre1_bytes" ] ||
		fail "second page-server pre-dump is not incremental"
	assert_coverage_committed "$source_pre2"
	if [ "$coverage_pre2_bytes" -le 0 ] || [ $((coverage_pre2_bytes * 64)) -ge "$target_pre1_bytes" ]; then
		fail "second source-side coverage is not compact"
	fi
	[ -L "$target_pre2/parent" ] ||
		fail "second destination pre-dump is not linked to its parent"

	dirty_page_generation "$target_pre2" "$base/toggle-address" ||
		fail "could not dirty a page before the final dump"

	"${CRIU_CMD[@]}" dump -D "$final" -o dump.log -t "$PID" -v4 --track-mem \
		--prev-images-dir ../source-pre2 ||
		fail "multiround final local dump failed"
	grep -q "Using remote parent coverage" "$final/dump.log" ||
		fail "multiround final dump did not select remote coverage"

	run_image_tool check-image "$final" "$PID" "$ORACLE_STATE" ||
		fail "final image has incorrect generation placement"
	final_bytes=$(sum_pages_bytes "$final")
	echo "multiround final pages bytes: $final_bytes"
	[ "$final_bytes" -gt 0 ] ||
		fail "multiround final dump contains no dirty-page payload"
	[ "$final_bytes" -le $((LOCAL_CONTROL_FINAL_BYTES * 4)) ] ||
		fail "multiround final dump is unexpectedly large"
	[ $((final_bytes * 4)) -lt "$target_pre1_bytes" ] ||
		fail "multiround final dump fell back toward a full image"

	mkdir -p "$base/target-final"
	cp -a "$final/." "$base/target-final/"
	rm -f "$base/target-final/parent"
	ln -s ../target-pre2 "$base/target-final/parent"
	"${CRIU_CMD[@]}" restore -D "$base/target-final" -o restore.log -v4 -d ||
		fail "multiround destination image failed to restore"
	stop_test "multiround remote-parent incremental restore"

	MULTIROUND_PRE1_BYTES="$target_pre1_bytes"
	MULTIROUND_PRE2_BYTES="$target_pre2_bytes"
	MULTIROUND_COVERAGE_BYTES="$coverage_pre2_bytes"
	MULTIROUND_FINAL_BYTES="$final_bytes"
}

assert_no_coverage() {
	local directory="$1"

	if compgen -G "$directory/remote-parent-*.img" >/dev/null ||
	   compgen -G "$directory/.remote-parent-*.tmp.*" >/dev/null; then
		fail "failed round left published or temporary coverage"
	fi
}

run_image_write_failure() {
	local side="$1"
	local base="$WORK_DIR/failure-$side"
	local source_pre="$base/source-pre"
	local target_pre="$base/target-pre"
	local port

	mkdir -p "$source_pre" "$target_pre"
	start_test
	port=$(free_port)
	if [ "$side" = server ]; then
		CRIU_TEST_FAIL_IMAGE=pagemap LD_PRELOAD="$FAULT_LIBRARY" \
			start_page_server "$target_pre" "$port" >"$base/server-stderr.log" 2>&1
		if "${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" \
			-D "$source_pre" -o dump.log -t "$PID" -v4 --track-mem \
			--page-server --address 127.0.0.1 --port "$port"; then
			fail "source accepted a destination pagemap write failure"
		fi
		if wait "$PAGE_SERVER_PID"; then
			fail "page-server acknowledged failed image writes as success"
		fi
		PAGE_SERVER_PID=""
		grep -q TEST_FAULT "$base/server-stderr.log" ||
			fail "server fault injection did not execute"
	else
		start_page_server "$target_pre" "$port"
		if CRIU_TEST_FAIL_IMAGE=inventory LD_PRELOAD="$FAULT_LIBRARY" \
			"${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" \
			-D "$source_pre" -o dump.log -t "$PID" -v4 --track-mem \
			--page-server --address 127.0.0.1 --port "$port" \
			2>"$base/source-stderr.log"; then
			fail "source inventory write failure was ignored"
		fi
		finish_page_server "healthy destination failed during source-only fault"
		grep -q TEST_FAULT "$base/source-stderr.log" ||
			fail "source inventory fault injection did not execute"
	fi
	assert_no_coverage "$source_pre"
	kill -0 "$PID" 2>/dev/null || fail "failed pre-dump did not resume its workload"
	stop_test "$side write failure preserves workload"
	echo "FAILURE-REGRESSION PASS: $side write failure did not publish coverage"
}

run_disconnect_failure() {
	local when="$1"
	local base="$WORK_DIR/disconnect-$when"
	local source_pre="$base/source-pre"
	local target_pre="$base/target-pre"
	local port

	mkdir -p "$source_pre" "$target_pre"
	start_test
	port=$(free_port)
	CRIU_TEST_DISCONNECT="$when" LD_PRELOAD="$FAULT_LIBRARY" \
		start_page_server "$target_pre" "$port" >"$base/server-stderr.log" 2>&1
	if "${CRIU_CMD[@]}" pre-dump --pre-dump-mode "$PRE_DUMP_MODE" \
		-D "$source_pre" -o dump.log -t "$PID" -v4 --track-mem \
		--page-server --address 127.0.0.1 --port "$port"; then
		fail "source accepted a disconnected page server ($when)"
	fi
	if wait "$PAGE_SERVER_PID"; then
		fail "disconnected server returned success"
	fi
	PAGE_SERVER_PID=""
	grep -q 'TEST_FAULT: page server disconnected' "$base/server-stderr.log" ||
		fail "disconnect injection did not execute"
	assert_no_coverage "$source_pre"
	kill -0 "$PID" 2>/dev/null || fail "disconnect did not resume workload"
	stop_test "$when disconnect preserves workload"
	echo "FAILURE-REGRESSION PASS: disconnect-$when did not publish coverage"
}

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
BASE_PAGE_LAUNCHER="$PWD/$WORK_DIR/base-page-launcher"
"${CC:-cc}" -Wall -Wextra -Werror base_page_launcher.c -o "$BASE_PAGE_LAUNCHER"
FAULT_LIBRARY="$PWD/$WORK_DIR/fail-image-write.so"
"${CC:-cc}" -shared -fPIC -Wall -Wextra -Werror fail_image_write.c -ldl -o "$FAULT_LIBRARY"

LOCAL_CONTROL_FINAL_BYTES=0
REMOTE_PARENT_COVERAGE_BYTES=0
REMOTE_PARENT_FINAL_BYTES=0
REMOTE_PARENT_PRE_BYTES=0
MULTIROUND_PRE1_BYTES=0
MULTIROUND_PRE2_BYTES=0
MULTIROUND_COVERAGE_BYTES=0
MULTIROUND_FINAL_BYTES=0

run_local_parent_control
run_remote_parent_regression
run_remote_parent_multiround_regression
run_image_write_failure server
run_image_write_failure source
run_disconnect_failure transfer
run_disconnect_failure close

cat <<EOF
Remote-parent regression PASSED
  local incremental final:    ${LOCAL_CONTROL_FINAL_BYTES} bytes
  remote pre-dump payload:    ${REMOTE_PARENT_PRE_BYTES} bytes
  remote coverage metadata:   ${REMOTE_PARENT_COVERAGE_BYTES} bytes
  remote-parent local final:  ${REMOTE_PARENT_FINAL_BYTES} bytes
  chained remote pre1:        ${MULTIROUND_PRE1_BYTES} bytes
  chained remote pre2:        ${MULTIROUND_PRE2_BYTES} bytes
  chained coverage metadata:  ${MULTIROUND_COVERAGE_BYTES} bytes
  chained local final:        ${MULTIROUND_FINAL_BYTES} bytes
EOF

if [ "${KEEP_WORK_DIR:-0}" != 1 ]; then
	rm -rf "$WORK_DIR"
else
	echo "Kept work directory: $WORK_DIR"
fi
