#!/bin/bash
# This script tries to run criu with different options to ensure
# the configuration file and option handling does not break.
#
# The options have been selected by looking at the existing
# test code coverage and missing code coverage should be handled
# by the options used in this file.
#
# Most calls only check for crashes and allow a return value of 1.
# The CUDA cases also check for the expected validation errors.

set -xbm

# shellcheck source=test/others/env.sh
source ../env.sh

if [ ! -d /etc/criu ]; then
	mkdir -p /etc/criu
fi

if [ ! -e /etc/criu/default.conf ]; then
	touch /etc/criu/default.conf
fi

# This tries to capture any exit codes other than 0 and 1
# Especially looking for crashes
trap '
RESULT=$?
if [[ $RESULT -gt 1 ]]; then
	echo "unexpected exit code $RESULT"
	exit 2
fi
' CHLD

# Just some random combination of flags
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -v0
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf conf1.test
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf1.test
$CRIU check --pre-dump-mode invalid --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf1.test
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf conf2.test
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf2.test
$CRIU check --pre-dump-mode invalid --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf2.test
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf conf3.test
$CRIU check --pre-dump-mode splice --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf3.test
$CRIU check --pre-dump-mode invalid --auto-dedup --page-server --track-mem --display-stats -v0 --conf=conf3.test
$CRIU check --no-default-config
$CRIU check --no-default-config --config=conf
$CRIU check --no-default-config --config=conf1.test
$CRIU check --no-default-config --config=conf1.test --help
$CRIU check --no-default-config --config=conf1.test --h
$CRIU check --no-default-config --config=conf2.test
$CRIU check --no-default-config --config=conf2.test --help
$CRIU check --no-default-config --config=conf2.test --h
$CRIU check --no-default-config --config=conf3.test
$CRIU check --no-default-config --config=conf3.test --help
$CRIU check --no-default-config --config=conf3.test --h

if [ ! -e "$HOME"/.criu.default ]; then
	touch "$HOME"/.criu.default
fi
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -v0 -s -t "-1"
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -S -R -vvvvvv
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -J invalidjoin-invalid
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -d -r
$CRIU check --pre-dump-mode read --auto-dedup --page-server --track-mem --display-stats -d -r none
unset HOME
$CRIU check --close
export HOME=/ROOOOT
$CRIU check --close
$CRIU check --port
$CRIU check --port 20000
$CRIU check --port some-port -l
CRIU_CONFIG_FILE=conf $CRIU check --port some-port -l
CRIU_CONFIG_FILE=conf1.test $CRIU check
CRIU_CONFIG_FILE=conf2.test $CRIU check
CRIU_CONFIG_FILE=conf3.test $CRIU check
CRIU_CONFIG_FILE=conf1.test $CRIU check --port some-port -l
CRIU_CONFIG_FILE=conf2.test $CRIU check --port some-port -l
CRIU_CONFIG_FILE=conf3.test $CRIU check --port some-port -l
$CRIU check --ms -L
CRIU_DEPRECATED=1 $CRIU check --ms
CRIU_DEPRECATED=1 $CRIU check
$CRIU check -l
$CRIU check -l 17
$CRIU check -L
$CRIU check -L 13
$CRIU check -L /tmp
$CRIU check --skip-mnt
$CRIU check --skip-mnt 13
$CRIU check --skip-mnt -13
$CRIU check --skip-mnt /tmp
$CRIU check --force-irmap --link-remap --evasive-devices
$CRIU check -M 1:2 --status-fd
$CRIU check -M 1:2 --status-fd 1 --ps-socket 1
$CRIU check -M 1:2 --status-fd 1 --ps-socket 1 -D
$CRIU check -M 1:2 --status-fd 1 --ps-socket 1 --port 4242
$CRIU check -M 1:2 --status-fd 1 --ps-socket one
$CRIU check -M 1:2 --status-fd one
$CRIU check --cgroup-props conf.test --cgroup-props-file conf.test
$CRIU -V
$CRIU dump --file-validation
$CRIU restore --file-validation 1
$CRIU check --file-validation filesizefilesize
$CRIU dump --file-validation filesize
$CRIU restore --file-validation buildid
$CRIU check --file-validation buildid --deprecated

# CUDA options are parsed during plugin initialization, not by "criu check".
if [ "$(uname -m)" = x86_64 ] && [ "${COMPAT_TEST:-}" != y ] && \
	[ -f "$BASE_DIR/plugins/cuda/cuda_plugin.so" ]; then
	(
		trap - CHLD
		CUDA_WORK=$(mktemp -d) || exit 1
		trap 'rm -rf "$CUDA_WORK"' EXIT

		for option in backend=invalid backend= backend \
			timeout=invalid timeout= timeout timeout=-1 timeout=-18446744073709551615 \
			timeout=4294967296 timeout=18446744073709551616 timeout=1x 'timeout= 1' \
			device-map=auto; do
			# Validation precedes task collection; use a nonexistent PID.
			rm -f "$CUDA_WORK/dump.log"
			timeout --kill-after=1s 10s "$CRIU" dump --no-default-config \
				--libdir "$BASE_DIR/plugins/cuda" --images-dir "$CUDA_WORK" \
				--log-file dump.log --tree 2147483647 \
				"--plugin-option=cuda_plugin.$option"
			status=$?
			if [ "$status" -ne 1 ] || ! grep -Eq \
				'Invalid cuda_plugin\.(backend|timeout) value|cuda_plugin\.(backend|timeout) requires a value|cuda_plugin.device-map is valid only during restore' \
				"$CUDA_WORK/dump.log"; then
				cat "$CUDA_WORK/dump.log"
				echo "cuda_plugin.$option did not report the expected validation error (status $status)"
				exit 1
			fi
		done
	) || exit 1
fi
exit 0
