#!/bin/sh

[ "$CRTOOLS_SCRIPT_ACTION" = post-dump ] || exit 0

#
# Special code to inform zdtm that we're
# done and should proceed testing treating
# non-zero return as known case.
exit 32
