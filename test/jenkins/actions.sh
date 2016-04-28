# Check how crit de/encodes images
set -e
source `dirname $0`/criu-lib.sh
# prep
rm -f actions_called.txt
./test/zdtm.py run -t zdtm/static/env00 --script "$(pwd)/test/show_action.sh" || fail
./test/check_actions.py || fail
exit 0
