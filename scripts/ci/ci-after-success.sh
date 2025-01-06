#!/bin/sh
set -x -e

# We only need to run the below for gcov-enabled builds
test -z "$GCOV" && exit 0

sudo apt-get install -qq -y lcov
gem install coveralls-lcov
sudo lcov --directory ../.. --capture --output-file coverage.info --ignore-errors graph
coveralls-lcov coverage.info
