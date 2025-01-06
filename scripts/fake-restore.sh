#!/bin/bash
#
# A stupid script to abort restore at the very end. Useful to test
# restore w/o letting the restored processes continue running. E.g.
# can be used to measure the restore time.
#
# Usage:
# criu restore <options> --action-script $(pwd)/scripts/fake-restore.sh
#
if [ "$CRTOOLS_SCRIPT_ACTION" == "post-restore" ]; then
	touch restore-succeeded
	exit 1
else
	exit 0
fi
