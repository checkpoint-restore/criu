#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source ../env.sh

make clean
touch testfile
chmod +w testfile
bash -c 'exec 3<testfile; while :; do sleep 1; done' &
testpid=$!
if ! "$criu" dump --tree=$testpid --shell-job --verbosity=4 --log-file=dump.log
then
    kill $testpid
    echo "Failed to dump process as expected"
    echo FAIL
    exit 1
fi
chmod -w testfile
if "$criu" restore --restore-detached --shell-job --verbosity=4 --log-file=restore-expected-fail.log
then
    kill $testpid
    echo "Unexpectedly restored process with reference to a file who's r/w/x perms changed when --skip-file-rwx-check option was not used"
    echo FAIL
    exit 1
fi
if ! "$criu" restore --skip-file-rwx-check --restore-detached --shell-job --verbosity=4 --log-file=restore.log
then
    echo "Failed to restore process with reference to a file who's r/w/x perms changed when --skip-file-rwx-check option was used"
    echo FAIL
    exit 1
fi
kill $testpid
echo PASS
