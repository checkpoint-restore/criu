#!/bin/sh

set -x

cat /proc/self/mountinfo

chmod 0777 test
chmod 0777 test/zdtm/transition/
chmod 0777 test/zdtm/static

./test/zdtm.py run -a --keep-going -k always --parallel 4 -x zdtm/static/rtc "$@"
ret=$?

for i in `find / -name 'asan.log*'`; do
	echo $i;
	echo ========================================
	cat $i;
	echo ========================================
	ret=1;
done;
exit $ret
