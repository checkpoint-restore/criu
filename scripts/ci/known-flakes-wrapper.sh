#!/bin/bash

# This is a wrapper script to re-run tests for known flakes.
# Known flake error messages can be added to the array KNOWN_FLAKES
# and the script will re-run the tests if one of the known flake
# error messages appears.
# The script will try to re-run the failing tests for $max_retries.
# Most used CI systems have a time limit, so max_retries should
# probably not be larger than 3. If a test fails for 3 times maybe
# something really needs to be fixed.
# Motivation for this script was that we currently just re-run CI
# if we see a known flake. This script tries to automate the step
# of automatically re-running CI for known flakes.

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <actual-script>" >&2
	exit 1
fi

KNOWN_FLAKES[0]="page-xfer: Can't read pagemap from socket: Input/output error"
KNOWN_FLAKES[1]="tcp.c:133: can't connect to server (errno = 106 (Transport endpoint is already connected))"
#KNOWN_FLAKES[2]="false" # replace with an error message of a known flake

retry_counter=0
max_retries=3
RESULT=1

LOG=$(mktemp)
trap 'rm -f ${LOG}' EXIT

while true; do
	if [ ! -e "${LOG}" ]; then
		LOG=$(mktemp)
	fi
	UNKNOWN_ERROR=1
	echo "Starting run ${retry_counter} of ${1}"
	"${1}" | tee "${LOG}"
	RESULT=${PIPESTATUS[0]}
	if [ "${RESULT}" -eq 0 ]; then
		exit 0
	fi
	echo "Run ${retry_counter} of ${1} exited with ${RESULT}"
	for flake in "${KNOWN_FLAKES[@]}"; do
		if grep -q "${flake}" "$LOG"; then
			UNKNOWN_ERROR=0
			echo "Found known flake: ${flake}"
			break
		fi
	done
	if [ "${UNKNOWN_ERROR}" -eq 1 ]; then
		exit "${RESULT}"
	fi
	(( retry_counter+=1 ))
	if [ "${retry_counter}" -gt "${max_retries}" ]; then
		exit "${RESULT}"
	fi
	echo "Rerunning ${1}"
	rm -f "${LOG}"
done

exit "${RESULT}"
