#!/bin/sh

set -e -x

./piggie

./src/test/test `pidof piggie`
