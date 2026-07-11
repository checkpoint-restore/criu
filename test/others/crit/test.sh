#!/bin/bash
# shellcheck disable=SC2002

set -ex

# shellcheck source=test/others/env.sh
source ../env.sh

images_list=()
RESTORED_PID=""

function cleanup_restored_process {
	if [ -z "$RESTORED_PID" ]; then
		return
	fi
	if kill -0 "$RESTORED_PID" 2>/dev/null; then
		kill -KILL "$RESTORED_PID" 2>/dev/null || true
	fi
	RESTORED_PID=""
}

trap cleanup_restored_process EXIT

function gen_imgs {
	PID=$(../loop)
	if ! $CRIU dump --no-default-config -v4 -o dump.log -D ./ -t "$PID"; then
		echo "Failed to checkpoint process $PID"
		if [ -f dump.log ]; then
			cat dump.log
		fi
		kill -9 "$PID" 2>/dev/null || true
		exit 1
	fi

	images_list=(./*.img)
	if [ "${#images_list[@]}" -eq 0 ]; then
		echo "Failed to generate images"
		exit 1
	fi
}

function run_test1 {
	for x in "${images_list[@]}"
	do
		echo "=== $x"
		if [[ $x == *pages* ]]; then
			echo "skip"
			continue
		fi

		echo "  -- to json"
		$CRIT decode -o "$x"".json" --pretty < "$x" || exit $?
		echo "  -- to img"
		$CRIT encode -i "$x"".json" > "$x"".json.img" || exit $?
		echo "  -- cmp"
		cmp "$x" "$x"".json.img" || exit $?

		echo "=== done"
	done
}


function run_test2 {
	PROTO_IN="${images_list[0]}"
	JSON_IN=$(mktemp -p ./ tmp.XXXXXXXXXX.json)
	OUT=$(mktemp -p ./ tmp.XXXXXXXXXX.log)

	# prepare
	${CRIT} decode -i "${PROTO_IN}" -o "${JSON_IN}"

	# show info about image
	${CRIT} info "${PROTO_IN}"

	# proto in - json out decode
	cat "${PROTO_IN}" | ${CRIT} decode || exit 1
	cat "${PROTO_IN}" | ${CRIT} decode -o "${OUT}" || exit 1
	cat "${PROTO_IN}" | ${CRIT} decode > "${OUT}" || exit 1
	${CRIT} decode -i "${PROTO_IN}" || exit 1
	${CRIT} decode -i "${PROTO_IN}" -o "${OUT}" || exit 1
	${CRIT} decode -i "${PROTO_IN}" > "${OUT}" || exit 1
	${CRIT} decode < "${PROTO_IN}" || exit 1
	${CRIT} decode -o "${OUT}" < "${PROTO_IN}" || exit 1
	${CRIT} decode < "${PROTO_IN}" > "${OUT}" || exit 1

	# proto in - json out encode -> should fail
	cat "${PROTO_IN}" | ${CRIT} encode || true
	cat "${PROTO_IN}" | ${CRIT} encode -o "${OUT}" || true
	cat "${PROTO_IN}" | ${CRIT} encode > "${OUT}" || true
	${CRIT} encode -i "${PROTO_IN}" || true
	${CRIT} encode -i "${PROTO_IN}" -o "${OUT}" || true
	${CRIT} encode -i "${PROTO_IN}" > "${OUT}" || true

	# json in - proto out encode
	cat "${JSON_IN}" | ${CRIT} encode || exit 1
	cat "${JSON_IN}" | ${CRIT} encode -o "${OUT}" || exit 1
	cat "${JSON_IN}" | ${CRIT} encode > "${OUT}" || exit 1
	${CRIT} encode -i "${JSON_IN}" || exit 1
	${CRIT} encode -i "${JSON_IN}" -o "${OUT}" || exit 1
	${CRIT} encode -i "${JSON_IN}" > "${OUT}" || exit 1
	${CRIT} encode < "${JSON_IN}" || exit 1
	${CRIT} encode -o "${OUT}" < "${JSON_IN}" || exit 1
	${CRIT} encode < "${JSON_IN}" > "${OUT}" || exit 1

	# json in - proto out decode -> should fail
	cat "${JSON_IN}" | ${CRIT} decode || true
	cat "${JSON_IN}" | ${CRIT} decode -o "${OUT}" || true
	cat "${JSON_IN}" | ${CRIT} decode > "${OUT}" || true
	${CRIT} decode -i "${JSON_IN}" || true
	${CRIT} decode -i "${JSON_IN}" -o "${OUT}" || true
	${CRIT} decode -i "${JSON_IN}" > "${OUT}" || true

	# explore image directory
	${CRIT} x ./ ps || exit 1
	${CRIT} x ./ fds || exit 1
	${CRIT} x ./ mems || exit 1
	${CRIT} x ./ rss || exit 1
}

ZDTM_DIR="${BASE_DIR}/test/zdtm/static"
CRIT_TEST_DIR="${BASE_DIR}/test/others/crit"
COMPRESSION_IMAGE_HELPER="${CRIT_TEST_DIR}/compression_image_helpers.py"
CRIT_TRANSACTION_TESTS="${CRIT_TEST_DIR}/crit_transaction_tests.py"
CRIT_COMPRESSION_TESTS="${CRIT_TEST_DIR}/crit_compression_tests.py"

function dump_test_process {
	# Dump compress_pages02 (covers 8 mapping types: anonymous,
	# zero-filled, shared anonymous, file-backed private/shared,
	# memfd, read-only, PROT_NONE guard) into the given directory.
	# Prints the PID on success.
	local dir=$1; shift
	local pid

	if ! make -C "$ZDTM_DIR" compress_pages02 > /dev/null 2>&1; then
		echo "FAIL: failed to build compress_pages02"
		exit 1
	fi

	# Clean stale marker files and run from the test directory
	# so zdtm pidfile rename works (same filesystem).
	rm -f "$dir"/test.out* "$dir"/test.pid "$dir"/test.file

	if ! (cd "$dir" && "$ZDTM_DIR/compress_pages02" \
		--pidfile=test.pid \
		--outfile=test.out \
		--filename=test.file); then
		echo "FAIL: failed to start compress_pages02"
		cat "$dir/test.out" 2>/dev/null
		exit 1
	fi

	# Wait for pidfile
	local i=0
	while [ $i -lt 50 ]; do
		if [ -f "$dir/test.pid" ]; then
			break
		fi
		sleep 0.1
		i=$((i + 1))
	done

	pid=$(cat "$dir/test.pid" 2>/dev/null)
	if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
		echo "FAIL: test process didn't start"
		cat "$dir/test.out" 2>/dev/null
		exit 1
	fi

	if ! $CRIU dump --no-default-config -v4 -o dump.log -D "$dir" \
			-t "$pid" --shell-job "$@"; then
		echo "FAIL: dump into $dir"
		if [ -f "$dir/dump.log" ]; then
			cat "$dir/dump.log"
		fi
		kill -9 "$pid" 2>/dev/null || true
		exit 1
	fi
	echo "$pid"
}

function restore_and_verify {
	# Restore from directory, send SIGTERM so compress_pages02
	# verifies its own memory, then check the test output for PASS.
	local dir=$1
	local i
	local pid
	local verified=0

	if ! $CRIU restore --no-default-config -v4 -o restore.log -D "$dir" \
			--shell-job -d; then
		echo "FAIL: restore from $dir"
		cat "$dir/restore.log"
		exit 1
	fi

	# Get the root PID from the pstree image
	pid=$($CRIT decode -i "$dir/pstree.img" 2>/dev/null |
		grep -o '"pid": [0-9]*' | head -1 | grep -o '[0-9]*')

	if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
		echo "FAIL: restored process not running from $dir (pid=$pid)"
		exit 1
	fi
	RESTORED_PID="$pid"

	# Send SIGTERM so compress_pages02 verifies all memory
	# regions (zero, pattern, shared, file, memfd, readonly,
	# guard) then writes PASS/FAIL to its output file.
	if ! kill -TERM "$pid" 2>/dev/null; then
		echo "FAIL: unable to signal restored process $pid from $dir"
		exit 1
	fi
	for ((i = 0; i < 100; i++)); do
		if grep -q PASS "$dir/test.out" 2>/dev/null; then
			verified=1
			break
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done

	if [ "$verified" -ne 1 ]; then
		echo "FAIL: memory verification failed after restore from $dir"
		cat "$dir/test.out" 2>/dev/null
		exit 1
	fi

	# The workload normally exits immediately after publishing PASS. Bound the
	# wait so a broken test cannot leak into subsequent CRIT cases.
	for ((i = 0; i < 50; i++)); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	RESTORED_PID=""
}

function pages_checksum {
	# Print md5sum of all pages-*.img files in a directory.
	# This captures the raw page content for comparison.
	cat "$1"/pages-*.img | md5sum | awk '{print $1}'
}

function assert_inventory_version {
	local dir=$1
	local expected=$2

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		assert-inventory-version "$dir" "$expected"
}

function make_sparse_pagemap_image {
	local dir=$1
	local compressed=$2

	rm -rf "$dir"
	mkdir -p "$dir"

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		make-sparse-pagemap "$dir" "$compressed"
}

function make_threshold_pagemap_image {
	local dir=$1

	rm -rf "$dir"
	mkdir -p "$dir"

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		make-threshold-pagemap "$dir"
}

function make_truncated_uncompressed_entry_image {
	local dir=$1

	rm -rf "$dir"
	mkdir -p "$dir"

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		make-truncated-uncompressed "$dir"
}

function assert_sparse_pagemap_payload {
	local dir=$1
	local expected_size=$2
	local expected_md5=$3
	local actual_size
	local actual_md5

	actual_size=$(stat -c %s "$dir/pages-1.img")
	if [ "$actual_size" != "$expected_size" ]; then
		echo "FAIL: $dir/pages-1.img size is $actual_size, expected $expected_size"
		exit 1
	fi

	actual_md5=$(md5sum "$dir/pages-1.img" | awk '{print $1}')
	if [ "$actual_md5" != "$expected_md5" ]; then
		echo "FAIL: $dir/pages-1.img checksum is $actual_md5, expected $expected_md5"
		exit 1
	fi
}

function assert_pagemap_entry_uncompressed {
	local dir=$1

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		assert-entry-uncompressed "$dir"
}

function assert_region_pagemap {
	local dir=$1

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		assert-region-pagemap "$dir"
}

function make_malformed_compressed_image {
	local dir=$1
	local kind=$2

	rm -rf "$dir"
	mkdir -p "$dir"

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		make-malformed-compressed "$dir" "$kind"
}

function make_transactional_compress_image {
	local dir=$1

	rm -rf "$dir"
	mkdir -p "$dir"

	PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		make-transactional-compress "$dir"
}

function image_set_checksum {
	(cd "$1" && sha256sum ./*.img) | sha256sum | awk '{print $1}'
}

function assert_no_transaction_files {
	local dir=$1
	local file

	file=$(find "$dir" -maxdepth 1 -name '.*.crit-*' -print -quit)
	if [ -n "$file" ]; then
		echo "FAIL: transaction file was not removed: $file"
		exit 1
	fi
}

function test_commit_transactions {
	PYTHONPATH="${BASE_DIR}/lib:${BASE_DIR}/crit" \
		python3 "$CRIT_TRANSACTION_TESTS" -v
}

function test_compress_regressions {
	PYTHONPATH="${BASE_DIR}/lib:${BASE_DIR}/crit" \
		python3 "$CRIT_COMPRESSION_TESTS"
}

function run_test_compress {
	local page_size
	page_size=$(getconf PAGESIZE)

	echo "=== compress/decompress tests ==="

	# -------------------------------------------------------
	# Test 1: dump -c -> decompress -> restore
	# -------------------------------------------------------
	echo "  -- Test 1: compressed dump -> decompress -> restore"
	dump_test_process comp/ -c > /dev/null

	$CRIT decompress comp/ || exit 1
	assert_inventory_version comp/ 2

	# Verify backup files exist
	ls comp/pages-*.img.bak > /dev/null 2>&1 || { echo "FAIL: no pages backup"; exit 1; }
	ls comp/pagemap-*.img.bak > /dev/null 2>&1 || { echo "FAIL: no pagemap backup"; exit 1; }
	ls comp/inventory.img.bak > /dev/null 2>&1 || { echo "FAIL: no inventory backup"; exit 1; }

	restore_and_verify comp/
	echo "     PASS"

	# -------------------------------------------------------
	# Test 2: dump uncompressed -> compress -> restore
	# -------------------------------------------------------
	echo "  -- Test 2: uncompressed dump -> compress -> restore"
	dump_test_process uncomp/ > /dev/null

	$CRIT compress uncomp/ --in-place || exit 1
	assert_inventory_version uncomp/ 3

	# Verify no backup files with --in-place
	if ls uncomp/*.bak > /dev/null 2>&1; then
		echo "FAIL: backup files created with --in-place"
		exit 1
	fi

	restore_and_verify uncomp/
	echo "     PASS"

	# -------------------------------------------------------
	# Test 3: compress already compressed, decompress already decompressed
	# -------------------------------------------------------
	echo "  -- Test 3: compress already compressed, decompress already decompressed"
	$CRIT compress uncomp/ --in-place 2>&1 | grep -q "already compressed" || {
		echo "FAIL: compress should report already compressed"
		exit 1
	}
	$CRIT decompress comp/ 2>&1 | grep -q "already decompressed" || {
		echo "FAIL: decompress should report already decompressed"
		exit 1
	}
	echo "     PASS"

	# -------------------------------------------------------
	# Test 4: compress -> decompress -> compress produces same pages
	# -------------------------------------------------------
	echo "  -- Test 4: compress -> decompress -> compress stability"
	rm -rf cdc/
	mkdir -p cdc/
	dump_test_process cdc/ > /dev/null

	$CRIT compress cdc/ --in-place || exit 1
	local sum1
	sum1=$(pages_checksum cdc/)

	$CRIT decompress cdc/ --in-place || exit 1
	assert_inventory_version cdc/ 2
	$CRIT compress cdc/ --in-place || exit 1
	assert_inventory_version cdc/ 3
	local sum2
	sum2=$(pages_checksum cdc/)

	if [ "$sum1" != "$sum2" ]; then
		echo "FAIL: compress->decompress->compress changed pages data"
		echo "  first:  $sum1"
		echo "  second: $sum2"
		exit 1
	fi

	restore_and_verify cdc/
	echo "     PASS"

	# -------------------------------------------------------
	# Test 5: decompress -> compress -> decompress produces same pages
	# -------------------------------------------------------
	echo "  -- Test 5: decompress -> compress -> decompress stability"
	rm -rf dcd/
	mkdir -p dcd/
	dump_test_process dcd/ -c > /dev/null

	$CRIT decompress dcd/ --in-place || exit 1
	assert_inventory_version dcd/ 2
	local sum3
	sum3=$(pages_checksum dcd/)

	$CRIT compress dcd/ --in-place || exit 1
	assert_inventory_version dcd/ 3
	$CRIT decompress dcd/ --in-place || exit 1
	assert_inventory_version dcd/ 2
	local sum4
	sum4=$(pages_checksum dcd/)

	if [ "$sum3" != "$sum4" ]; then
		echo "FAIL: decompress->compress->decompress changed pages data"
		echo "  first:  $sum3"
		echo "  second: $sum4"
		exit 1
	fi

	restore_and_verify dcd/
	echo "     PASS"

	# -------------------------------------------------------
	# Test 6: CRIT must not consume pages payload for sparse
	# pagemap entries without PE_PRESENT, including legacy
	# in_parent entries with no flags field.
	# -------------------------------------------------------
	echo "  -- Test 6: sparse pagemap entries have no pages payload"
	local raw_md5
	local zero_md5
	raw_md5=$(PYTHONPATH="${BASE_DIR}/lib" \
		python3 "$COMPRESSION_IMAGE_HELPER" \
		expected-sparse-checksum raw-zero)
	zero_md5=$(PYTHONPATH="${BASE_DIR}/lib" \
		python3 "$COMPRESSION_IMAGE_HELPER" \
		expected-sparse-checksum two-raw)

	make_sparse_pagemap_image sparse-compress/ 0
	$CRIT compress sparse-compress/ --in-place || exit 1
	assert_inventory_version sparse-compress/ 3
	$CRIT decompress sparse-compress/ --in-place || exit 1
	# Parent entries may still resolve to compressed parent images, so CRIT
	# must retain the V1_2 reader gate after transforming the local payload.
	assert_inventory_version sparse-compress/ 3
	assert_sparse_pagemap_payload sparse-compress/ "$((page_size * 2))" "$zero_md5"

	make_sparse_pagemap_image sparse-decompress/ 1
	$CRIT decompress sparse-decompress/ --in-place || exit 1
	assert_inventory_version sparse-decompress/ 3
	assert_sparse_pagemap_payload sparse-decompress/ "$((page_size * 2))" "$raw_md5"
	echo "     PASS"

	# -------------------------------------------------------
	# Test 7: CRIT uses the same 7/8 raw fallback threshold as CRIU and
	# omits compression metadata when the complete entry stays raw.
	# -------------------------------------------------------
	echo "  -- Test 7: raw-only entries use ordinary pagemap representation"
	make_threshold_pagemap_image threshold-compress/
	local threshold_md5
	threshold_md5=$(md5sum threshold-compress/pages-1.img | awk '{print $1}')

	$CRIT compress threshold-compress/ --in-place || exit 1
	assert_inventory_version threshold-compress/ 3
	assert_pagemap_entry_uncompressed threshold-compress/
	assert_sparse_pagemap_payload threshold-compress/ "$page_size" "$threshold_md5"

	# A parent link means a parent image may still require compressed-image
	# readers even when every page in this directory is present and raw.
	cp -a threshold-compress/ threshold-parent/
	mkdir -p parent-placeholder/
	cp threshold-compress/inventory.img parent-placeholder/inventory.img
	ln -s ../parent-placeholder threshold-parent/parent
	$CRIT decompress threshold-parent/ --in-place || exit 1
	assert_inventory_version threshold-parent/ 3

	$CRIT decompress threshold-compress/ --in-place || exit 1
	assert_inventory_version threshold-compress/ 2
	assert_sparse_pagemap_payload threshold-compress/ "$page_size" "$threshold_md5"
	echo "     PASS"

	# -------------------------------------------------------
	# Test 8: CRIT must fail explicitly on a truncated
	# uncompressed payload copied through by decompress.
	# -------------------------------------------------------
	echo "  -- Test 8: truncated uncompressed payload is rejected"
	make_truncated_uncompressed_entry_image truncated-decompress/
	if $CRIT decompress truncated-decompress/ --in-place \
			> truncated-decompress.log 2>&1; then
		echo "FAIL: decompress accepted truncated pages payload"
		cat truncated-decompress.log
		exit 1
	fi
	grep -q "describes.*payload bytes" truncated-decompress.log || {
		echo "FAIL: decompress did not report the payload-size mismatch"
		cat truncated-decompress.log
		exit 1
	}
	echo "     PASS"

	# -------------------------------------------------------
	# Test 9: region-compressed images are transformed and
	# restored, including a final short region where present.
	# -------------------------------------------------------
	echo "  -- Test 9: region-compressed dump -> decompress -> restore"
	rm -rf region/
	mkdir -p region/
	dump_test_process region/ "--compress-region=$((page_size * 16))" > /dev/null
	assert_region_pagemap region/
	$CRIT decompress region/ --in-place || exit 1
	assert_inventory_version region/ 2
	restore_and_verify region/
	echo "     PASS"

	# -------------------------------------------------------
	# Test 10: reject malformed compressed metadata before
	# attempting any unbounded read or allocation.
	# -------------------------------------------------------
	echo "  -- Test 10: malformed compressed metadata is rejected"
	local kind
	for kind in oversize total count flags aligned-nonpresent region-limit region-count \
			region-final-oversize; do
		local dir="malformed-$kind"
		local before
		local after
		make_malformed_compressed_image "$dir/" "$kind"
		before=$(image_set_checksum "$dir/")
		if $CRIT decompress "$dir/" --in-place \
				> "$dir.log" 2>&1; then
			echo "FAIL: decompress accepted malformed metadata: $kind"
			cat "$dir.log"
			exit 1
		fi
		after=$(image_set_checksum "$dir/")
		if [ "$before" != "$after" ]; then
			echo "FAIL: malformed $kind image was modified"
			exit 1
		fi
		assert_no_transaction_files "$dir/"
	done
	echo "     PASS"

	# -------------------------------------------------------
	# Test 11: a failure in a later pages image leaves every
	# original image untouched for both transformations.
	# -------------------------------------------------------
	echo "  -- Test 11: transformations are transactional"
	local before
	local after

	make_malformed_compressed_image transaction-decompress/ transaction
	before=$(image_set_checksum transaction-decompress/)
	if $CRIT decompress transaction-decompress/ --in-place \
			> transaction-decompress.log 2>&1; then
		echo "FAIL: decompress accepted corrupt LZ4 payload"
		cat transaction-decompress.log
		exit 1
	fi
	after=$(image_set_checksum transaction-decompress/)
	if [ "$before" != "$after" ]; then
		echo "FAIL: failed decompression modified the image set"
		exit 1
	fi
	assert_no_transaction_files transaction-decompress/

	make_transactional_compress_image transaction-compress/
	before=$(image_set_checksum transaction-compress/)
	if $CRIT compress transaction-compress/ --in-place \
			> transaction-compress.log 2>&1; then
		echo "FAIL: compress accepted a truncated pages image"
		cat transaction-compress.log
		exit 1
	fi
	after=$(image_set_checksum transaction-compress/)
	if [ "$before" != "$after" ]; then
		echo "FAIL: failed compression modified the image set"
		exit 1
	fi
	assert_no_transaction_files transaction-compress/
	test_commit_transactions
	echo "     PASS"

	# -------------------------------------------------------
	# Test 12: offline compression observes restore invariants,
	# honors acceleration, preserves timestamps, and validates enums.
	# -------------------------------------------------------
	echo "  -- Test 12: CRIT compression regressions"
	test_compress_regressions
	echo "     PASS"

	echo "=== compress/decompress: ALL PASS ==="
}

${CRIT} --version

gen_imgs
run_test1
run_test2

# Skip compress/decompress tests if lz4 or CRIU compression is unavailable
if PYTHONPATH="${BASE_DIR}/lib" python3 "$COMPRESSION_IMAGE_HELPER" \
		has-lz4 2>/dev/null && \
		$CRIU check --no-default-config --feature compress 2>/dev/null; then
	mkdir -p comp/ uncomp/
	run_test_compress
else
	echo "=== Skipping compress/decompress tests (lz4 or CRIU compression not available) ==="
fi
