#!/bin/sh

set -eu

dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$work/cache/downloads"
for version in 1 2; do
	mkdir "$work/libnet-$version"
	echo "$version" > "$work/libnet-$version/version"
	cat > "$work/libnet-$version/configure" <<'EOF'
#!/bin/sh
set -eu

for arg; do
	case "$arg" in
	--prefix=*)
		prefix=${arg#--prefix=}
		;;
	esac
done

version=$(cat version)
cat > Makefile <<MAKEFILE
all:
	@true
install:
	@echo $version > $prefix/version
	@echo built >> $prefix/builds
MAKEFILE
EOF
	chmod +x "$work/libnet-$version/configure"
	tar -czf "$work/cache/downloads/libnet-$version.tar.gz" -C "$work" "libnet-$version"
done
# Both cached tarballs must predate every extraction/build stamp.
touch -t 200001010000 "$work/cache/downloads/"*

build_version()
{
	version=$1
	tarball="$work/cache/downloads/libnet-$version.tar.gz"
	checksum=$(sha256sum "$tarball" | cut -d ' ' -f 1)
	make -s -C "$dir" libnet O="$work/cache" J=1 \
		LIBNET_VERSION="$version" LIBNET_URL="${3:-file://$tarball}" \
		LIBNET_SHA256="${2:-$checksum}"
}

for version in 1 2 1; do
	build_version "$version"
	test "$(cat "$work/cache/install/version")" = "$version"
done
test "$(wc -l < "$work/cache/install/builds")" -eq 3

# Reusing the same source must leave the build cached.
build_version 1
test "$(wc -l < "$work/cache/install/builds")" -eq 3

# A different URL with the same archive name must also invalidate the build.
build_version 1 '' "file://$work/other/libnet-1.tar.gz"
test "$(wc -l < "$work/cache/install/builds")" -eq 4

# A new checksum must revalidate the cached tarball instead of reusing it.
if build_version 1 "$(printf '%064d' 0)" >"$work/checksum.log" 2>&1; then
	echo 'Accepted a cached tarball with the wrong checksum' >&2
	exit 1
fi
grep -q 'checksum did NOT match' "$work/checksum.log"
build_version 1
test "$(wc -l < "$work/cache/install/builds")" -eq 5

# Compiler flags can change the ABI without changing the reported target
# or version. Reject a cache populated with a different compiler command.
if make -s -C "$dir" libnet O="$work/cache" J=1 \
	CC="${CC:-cc} -DCRIU_TEST_CC_ID" LIBNET_VERSION=1 \
	LIBNET_URL="file://$tarball" LIBNET_SHA256="$checksum" >"$work/compiler.log" 2>&1; then
	echo 'Accepted a dependency cache built with a different compiler command' >&2
	exit 1
fi
grep -q 'built with a different compiler' "$work/compiler.log"

# A rejected compiler must leave the original cache reusable.
build_version 1
test "$(wc -l < "$work/cache/install/builds")" -eq 5

echo 'Static dependency cache checks PASS'
