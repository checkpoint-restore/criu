#!/bin/bash

cd ../.. || exit 1

failures=""

docker build -t criu-openj9-ubuntu-test:latest -f scripts/build/Dockerfile.openj9-ubuntu .
if ! docker run --rm --privileged criu-openj9-ubuntu-test:latest; then
	failures="$failures openj9-ubuntu"
fi

docker build -t criu-hotspot-alpine-test:latest -f scripts/build/Dockerfile.hotspot-alpine .
if ! docker run --rm --privileged criu-hotspot-alpine-test:latest; then
	failures="$failures hotspot-alpine"
fi

docker build -t criu-hotspot-ubuntu-test:latest -f scripts/build/Dockerfile.hotspot-ubuntu .
if ! docker run --rm --privileged criu-hotspot-ubuntu-test:latest; then
	failures="$failures hotspot-ubuntu"
fi

if [ -n "$failures" ]; then
	echo "Tests failed on $failures"
	exit 1
fi
