#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

rm -f "${SCRIPT_DIR}"/actions_called.txt
"${SCRIPT_DIR}"/../../zdtm.py run -t zdtm/static/env00 -f ns --script "$SCRIPT_DIR/show_action.sh" || exit 1
"${SCRIPT_DIR}"/check_actions.py || exit 1

exit 0
