# Check how crit de/encodes images
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all -f best -x maps04 -x cgroup02 --norst --keep always || fail

images_list=$(find "test/dump/" -name '*.img')
crit="./crit"

for x in $images_list
do
	[[ "$(basename $x)" == pages* ]] && continue

	echo "Check $x"

	$crit decode -o "$x"".json" < $x || fail
	$crit encode -i "$x"".json" > "$x"".json.img" || fail
	cmp "$x" "${x}.json.img" || _exit $x
	rm -f "${x}.json.img"

	$crit decode -o "$x"".json" --pretty < $x || fail
	$crit encode -i "$x"".json" > "$x"".json.img" || fail
	cmp "$x" "${x}.json.img" || fail
	rm -f "${x}.json.img"
done

echo "PASS"
exit 0
