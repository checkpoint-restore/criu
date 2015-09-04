source `dirname $0`/criu-lib.sh &&
prep &&
bash ./test/zdtm.sh -C -x '\(fpu\|mmx\|sse\|rtc\|ext_auto\)' &&
true || fail
