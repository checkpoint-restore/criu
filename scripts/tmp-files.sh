#!/bin/bash
#
# Script allows to save arbitrary files in CRIU dump dir and properly restore
# these files on CRIU restore cmd.
#
# Normally you need to call this script for files that can be lost between
# CRIU checkpoint and restore cmds. For example for files stored on non-tmpfs
# mount points. That's why this script is called tmp-files.
#
# You should call this script on both CRIU dump and restore cmds.
#
# Usage:
# criu dump <options> --action-script \
#     '$CRIU_SCRIPTS_PATH/tmp-files.sh /tmp/ycm_temp /home/user/.tmpfile.txt.swp'
# criu restore <options> --action-script $CRIU_SCRIPTS_PATH/tmp-files.sh
#
# Note: absolute path to tmp-files.sh should be supplied in --action-script with ''
#

POSTDUMP="post-dump"
PRERESTORE="pre-restore"
DUMPARGS="--create --absolute-names --gzip --no-unquote --no-wildcards --file"
RESTOREARGS="--extract --gzip --no-unquote --no-wildcards --absolute-names --directory / --file"
IMGFILE=$CRTOOLS_IMAGE_DIR"/tmpfiles.tar.gz"

MY_NAME=$(basename "$0")

case "$CRTOOLS_SCRIPT_ACTION" in
	$POSTDUMP )
		if [ "$#" -lt 1 ]; then
			echo "$MY_NAME: ERROR! No files are given."
			exit 1
		fi
		tar "$DUMPARGS" "$IMGFILE" -- "$@"
		exit $?
		;;
	$PRERESTORE )
		if [ "$#" -ne 0 ]; then
			echo "$MY_NAME: ERROR! Not expected script args."
			exit 1
		fi
		tar "$RESTOREARGS" "$IMGFILE"
		exit $?
		;;
esac

exit 0
