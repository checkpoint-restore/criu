#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source ../env.sh

make clean
touch testfile
chmod +w testfile
tail --follow testfile &
tailpid=$!
if ! "$criu" dump --tree=$tailpid --shell-job --verbosity=4 --log-file=dump.log
then
    kill $tailpid
    echo "Failed to dump process as expected"
    echo FAIL
    exit 1
fi
chmod -w testfile
if "$criu" restore --restore-detached --shell-job --verbosity=4 --log-file=restore-expected-fail.log
then
    kill $tailpid
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
kill $tailpid
echo PASS
