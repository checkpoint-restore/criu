#!/bin/bash
# $1 -- link name
# $2 -- file with namespace pid
if [ "$CRTOOLS_SCRIPT_ACTION" == "setup-namespaces" ]; then
	$(dirname $0)/addmv_raw.sh $1 $(cat $2)
else
	exit 0
fi
