#!/bin/sh
# A test to make sure "make uninstall" works as intended.

set -e
SELFDIR=$(dirname $(readlink -f $0))
DESTDIR=$SELFDIR/test.install-$$
cd $SELFDIR/../../..

set -x
make install DESTDIR=$DESTDIR
make uninstall DESTDIR=$DESTDIR
set +x

# There should be no files left (directories are OK for now)
# except protobuf under Python site-packages

ALLOW_RE='/python[0-9.]+/(site|dist)-packages/(google/.*|protobuf-[0-9.]+\.dist-info/.*)$'

LEFT=$(find "$DESTDIR" -type f | grep -vE "$ALLOW_RE" || true)

if [ -n "$LEFT" ]; then
	echo "Files left after uninstall:"
	echo "$LEFT"
	echo "FAIL"
	exit 1
fi

echo PASS
