#!/bin/bash
#
# Exercise the restore-time O_DIRECT page-read path.
#
# On restore criu probes the pages image with probe_pages_o_direct()
# (criu/pagemap.c) and, when the image lives on an O_DIRECT-capable filesystem,
# reads the pages with O_DIRECT and may select the io_submit-based engine
# (criu/pie/restorer.c), logging "O_DIRECT enabled on pages fd". Whether the
# image directory is O_DIRECT-capable depends on the runner's filesystem and
# nothing otherwise asserts the path was taken, so a regression in the
# selection would go unnoticed. Mount a dedicated ext4 loop device over the
# zdtm image directory and assert the marker. The marker proves O_DIRECT was
# selected for the page reads; it does not assert that the AIO restorer engine
# itself ran.
#
# The Makefile runs this in a private mount namespace (unshare -m), so the loop
# mount over the image directory stays isolated from the host and is released
# automatically when the test exits; only the backing image needs cleanup.
#
# Needs root, mkfs.ext4 and a filesystem that serves O_DIRECT; skips (exit 0)
# where any of that is unavailable. zdtm/transition/maps007 (host flavor) takes
# the async vma_io path that reaches the probe.

set -e -x -o pipefail

img=
# zdtm.py chdirs to test/ and writes images to dump/; this script runs in
# test/others/odirect/, so test/dump is ../../dump.
dumpdir=../../dump

skip() {
	echo "SKIP others/odirect: $1"
	exit 0
}

# The loop mount is freed when the mount namespace exits; only the image needs
# removal, including on an interrupted run (INT/TERM route through the EXIT trap).
# shellcheck disable=SC2329  # invoked via trap below
cleanup() {
	[ -n "$img" ] && rm -f "$img"
	return 0
}
trap cleanup EXIT
trap 'exit 1' INT TERM

[ "$(id -u)" = 0 ] || skip "needs root"
command -v mkfs.ext4 >/dev/null 2>&1 || skip "mkfs.ext4 not available"

img=$(mktemp ./odirect.img.XXXXXX)
# truncate keeps the image sparse, so it only occupies the blocks actually
# written. 768M clears maps007's 512M MEM_SIZE (faulted across a parent and a
# COW child) with headroom against an ENOSPC flake.
truncate -s 768M "$img"
mkfs.ext4 -qF "$img"

# Mount the O_DIRECT fs over the zdtm image dir (private mount ns, see Makefile).
mkdir -p "$dumpdir"
mount -o loop "$img" "$dumpdir" || skip "cannot mount loop device"

# Some kernels reject O_DIRECT even on ext4 (for example when CONFIG_AIO is
# off). bs=4096 is a valid O_DIRECT alignment on every architecture (criu
# aligns to the runtime PAGE_SIZE, which is >= 4096).
if ! dd if=/dev/zero of="$dumpdir/probe" bs=4096 count=1 status=none 2>/dev/null ||
	! dd if="$dumpdir/probe" of=/dev/null bs=4096 count=1 iflag=direct status=none 2>/dev/null; then
	skip "filesystem does not serve O_DIRECT"
fi
rm -f "$dumpdir/probe"

ret=0
../../zdtm.py run -t zdtm/transition/maps007 -f h --keep-img always || ret=$?
if [ "$ret" -ne 0 ]; then
	echo "FAIL others/odirect: maps007 checkpoint/restore failed (rc=$ret)"
	exit 1
fi

# grep an extended-regex over every restore log (find, since busybox grep has
# no --include).
log_has() {
	local f
	while IFS= read -r f; do
		if grep -qE "$1" "$f"; then
			return 0
		fi
	done < <(find "$dumpdir" -name '*.log')
	return 1
}

# Marker source: criu/pagemap.c "O_DIRECT enabled on pages fd". This is not a
# streaming restore and the filesystem serves O_DIRECT (probed above), so the
# marker is expected.
if log_has "O_DIRECT enabled on pages fd"; then
	echo "PASS others/odirect: O_DIRECT page-read path exercised"
	exit 0
fi

# The capability probe passed, so the only legitimate reason criu did not
# select O_DIRECT is that the kernel rejected it for the pages fd at runtime,
# which criu logs ("Failed to set O_DIRECT" / "O_DIRECT rejected at read
# time"). Treat that as a skip rather than a regression.
if log_has "Failed to set O_DIRECT|O_DIRECT rejected"; then
	echo "SKIP others/odirect: kernel rejected O_DIRECT for the pages fd"
	exit 0
fi

echo "FAIL others/odirect: O_DIRECT was not selected on restore"
exit 1
