#!/bin/bash
set -e -x

contrib/dependencies/dnf-packages.sh
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
	tar

# /tmp is no longer 755 in the rawhide container image and breaks CI - fix it
chmod 1777 /tmp
