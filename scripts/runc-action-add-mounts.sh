#!/bin/bash
#
# runc-action-add-mounts.sh — CRIU action-script wrapper for criu-move-mount.
#
# Purpose:
#   This script is intended to be used as CRIU's --action-script. On each
#   invocation it compiles criu-move-mount.c into a local binary and then
#   executes that binary so mount rules can be applied in pre-resume phase.
#
# Why compile at runtime:
#   - keeps deployment simple (only this script + C source are required)
#   - avoids relying on a pre-installed criu-move-mount binary path
#
# Usage:
#   criu restore --action-script /path/to/runc-action-add-mounts.sh
#
# Behavior:
#   1) Resolve SCRIPT_DIR from this script's location.
#   2) Expect source file at: $SCRIPT_DIR/criu-move-mount.c
#   3) Build binary to:      $SCRIPT_DIR/criu-move-mount
#   4) chmod +x binary and exec it.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source_file="$SCRIPT_DIR/criu-move-mount.c"
bin="$SCRIPT_DIR/criu-move-mount"
if [ ! -f "$source_file" ]; then
	echo "add-mounts: source file $source_file not found" >&2
	exit 1
fi

echo "Compiling $source_file..."
gcc -O2 -o "$bin" "$source_file"

if [ ! -f "$bin" ]; then
	echo "add-mounts: compilation failed, binary not created" >&2
	exit 1
fi

chmod +x "$bin"
exec "$bin"