#!/bin/bash

# Don't execute tests, which use maps04, they are executed by zdtm

set -e

#./run-predump-2.sh
./run-predump.sh
./run-snap-auto-dedup.sh
./run-snap-dedup-on-restore.sh
./run-snap-dedup.sh
#./run-snap-maps04.sh
./run-snap.sh
