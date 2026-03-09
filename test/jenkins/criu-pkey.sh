#!/bin/bash

# Check x86 PKU/pkey dump/restore coverage.
set -e
source `dirname $0`/criu-lib.sh

if [ "$(uname -m)" != "x86_64" ]; then
	echo "Skip pkey Jenkins job: x86_64 only"
	exit 0
fi

prep

for test in \
	zdtm/static/pkey_basic \
	zdtm/static/pkey_execute_only \
	zdtm/static/pkey_sparse_keys \
	zdtm/static/pkey_pkru_persist \
	zdtm/static/pkey_execute_only_mix
do
	./test/zdtm.py run -t "$test" --report report || fail
done
