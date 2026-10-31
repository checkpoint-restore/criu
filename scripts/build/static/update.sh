#!/bin/sh
#
# Update a static dependency to a new version: download its tarball and
# record the version and checksum in versions.mk.
#
# Usage: update.sh NAME VERSION
#   NAME is the variable prefix in versions.mk, e.g. LIBNL or UTIL_LINUX.
#   Run `make check-updates` in this directory to list available updates.

set -eu

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 NAME VERSION" >&2
	exit 1
fi

name=$1
version=$2

# These values become make assignments and sed replacement text.
case "$name" in
''|[!A-Z]*|*[!A-Z0-9_]*)
	echo "Invalid dependency name: $name" >&2
	exit 1
	;;
esac
case "$version" in
''|[!0-9]*|*[!0-9A-Za-z.+_-]*)
	echo "Invalid version: $version" >&2
	exit 1
	;;
esac

dir=$(dirname -- "$0")
versions="$dir/versions.mk"

if ! grep -q "^${name}_VERSION " "$versions"; then
	echo "Unknown dependency: $name" >&2
	exit 1
fi

url=$(make -s -C "$dir" print-url DEP="$name" "${name}_VERSION=$version")
tarball=$(mktemp)
trap 'rm -f "$tarball"' EXIT

echo "Downloading $url"
curl -fsSL --retry 3 "$url" -o "$tarball"
sha256=$(sha256sum "$tarball" | cut -d ' ' -f 1)

sed -i -E \
	-e "s/^(${name}_VERSION[[:space:]]+:= ).*/\\1$version/" \
	-e "s/^(${name}_SHA256[[:space:]]+:= ).*/\\1$sha256/" \
	"$versions"

echo "$name $version $sha256"
