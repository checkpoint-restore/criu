#!/bin/bash

# Check known fault injections
set -e
source `dirname $0`/criu-lib.sh
prep
./test//zdtm.py --set inhfd run --all --keep-going --report report -f h || fail
