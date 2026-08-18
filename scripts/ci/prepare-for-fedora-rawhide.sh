#!/bin/bash
set -e -x
# Disable fedora-cisco-openh264 repo because openh264 package signature verification
# fails on Fedora Rawhide due to mismatched GPG keys.
dnf config-manager setopt fedora-cisco-openh264.enabled=0 2>/dev/null || \
dnf config-manager --set-disabled fedora-cisco-openh264 2>/dev/null || true

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
