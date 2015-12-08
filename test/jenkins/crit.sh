# Check how crit de/encodes images
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all -f best -x maps04 -x cgroup02 --norst --keep always || fail

FAIL_LIST=""
images_list=$(find "test/dump/" -name '*.img')
crit="./crit"

function note()
{
	FAIL_LIST="${FAIL_LIST}\n$*"
}

for x in $images_list
do
	[[ "$(basename $x)" == pages* ]] && continue
	[[ "$(basename $x)" == route* ]] && continue
	[[ "$(basename $x)" == ifaddr* ]] && continue
	[[ "$(basename $x)" == iptables* ]] && continue
	[[ "$(basename $x)" == ip6tables* ]] && continue
	[[ "$(basename $x)" == *tar.gz* ]] && continue

	echo "Check $x"

	$crit decode -o "$x"".json" < "$x" || note "dec $x"
	$crit encode -i "$x"".json" > "${x}.json.img" || note "enc $x"
	cmp "$x" "${x}.json.img" || note "cmp $x"
	rm -f "${x}.json.img"

	$crit decode -o "$x"".json" --pretty < "$x" || note "show $x"
	$crit encode -i "$x"".json" > "${x}.json.img" || note "enc2 $x"
	cmp "$x" "${x}.json.img" || note "cmp2 $x"
	rm -f "${x}.json.img"
done

if [ -z "$FAIL_LIST" ]; then
	echo "PASS"
	exit 0
fi

echo -e "$FAIL_LIST"
echo "FAIL"
exit 1
