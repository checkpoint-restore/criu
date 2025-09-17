#!/bin/bash
set -e -x

COMMON_PACKAGES_LIST_FILE="${1:-contrib/dependencies/dnf-packages.txt}"

# SC2046 is "Quote this to prevent word splitting". We do want word splitting
# so that each line is passed as a separate argument
# shellcheck disable=SC2046
dnf install -y \
	diffutils \
	e2fsprogs \
	findutils \
	gawk \
	gzip \
	kmod \
	libselinux-utils \
	procps-ng \
	python3-pip \
	python-unversioned-command \
	redhat-rpm-config \
	sudo \
	tar \
	which \
	$(sed 's/\#.*$//' "${COMMON_PACKAGES_LIST_FILE}")

# /tmp is no longer 755 in the rawhide container image and breaks CI - fix it
chmod 1777 /tmp
