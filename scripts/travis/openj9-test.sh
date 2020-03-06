#!/bin/bash

cd ../..

failures=""

docker build -t criu-openj9-ubuntu-test:latest -f scripts/build/Dockerfile.openj9-ubuntu .
docker run --rm --privileged criu-openj9-ubuntu-test:latest
if [ $? -ne 0 ]; then
	failures=`echo "$failures ubuntu"`
fi

docker build -t criu-openj9-alpine-test:latest -f scripts/build/Dockerfile.openj9-alpine .
docker run --rm --privileged criu-openj9-alpine-test:latest
if [ $? -ne 0 ]; then
	failures=`echo "$failures alpine"`
fi

if [ -n "$failures" ]; then
	echo "Tests failed on $failures"
	exit 1
fi
