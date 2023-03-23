#!/bin/bash
touch action-hook-"$CRTOOLS_SCRIPT_ACTION"

vars=("E1" "E2" "E3" "E4")

for var in "${vars[@]}"
do
  if [ -n "${!var}" ]; then
    echo "${!var}" > "action-env-$var"
  fi
done

exit 0
