#!/bin/bash

echo "${CRTOOLS_SCRIPT_ACTION} ${CRTOOLS_IMAGE_DIR} ${CRTOOLS_INIT_PID}" \
	>> "$(dirname "$0")/actions_called.txt"
