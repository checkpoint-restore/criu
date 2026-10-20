#!/bin/sh

set -eu

dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Keep ELF inspection failures independent of the host's tool versions.
mkdir "$work/bin"
cat > "$work/bin/readelf" <<'EOF'
#!/bin/sh
if [ "$1" = "${READELF_FAIL:-}" ]; then
	exit 1
fi
case "$1" in
-l) printf '%s\n' "${PROGRAM_HEADERS:-}" ;;
-d) printf '%s\n' "${DYNAMIC_SECTION:-}" ;;
esac
EOF
cat > "$work/bin/nm" <<'EOF'
#!/bin/sh
printf '%s\n' '0 T LZ4_compress_default' '0 T nft_run_cmd_from_buffer' '0 T is_selinux_enabled'
EOF
chmod +x "$work/bin/readelf" "$work/bin/nm"
PATH="$work/bin:$PATH"
export PATH

"$dir/check-binary.sh" unused
for option in -l -d; do
	if READELF_FAIL="$option" "$dir/check-binary.sh" unused >"$work/check.log" 2>&1; then
		echo "Accepted a binary after readelf $option failed" >&2
		exit 1
	fi
	grep -q 'cannot read ELF' "$work/check.log"
done
if PROGRAM_HEADERS=INTERP "$dir/check-binary.sh" unused >"$work/check.log" 2>&1; then
	echo 'Accepted a binary with an ELF interpreter' >&2
	exit 1
fi
grep -q 'has an ELF interpreter' "$work/check.log"
if DYNAMIC_SECTION='(NEEDED)' "$dir/check-binary.sh" unused >"$work/check.log" 2>&1; then
	echo 'Accepted a binary with shared libraries' >&2
	exit 1
fi
grep -q 'depends on shared libraries' "$work/check.log"

# Invalid arguments must fail before make expands them or sed writes them.
# shellcheck disable=SC2016
for name in '' 'LIBNET.*' 'LIBNET$(error expanded)' 'libnet'; do
	if "$dir/update.sh" "$name" 1 >"$work/update.log" 2>&1; then
		echo "Accepted an invalid dependency name: $name" >&2
		exit 1
	fi
	grep -q 'Invalid dependency name:' "$work/update.log"
done
# shellcheck disable=SC2016
for version in '' '1&2' '1/2' '1$(error expanded)'; do
	if "$dir/update.sh" LIBNET "$version" >"$work/update.log" 2>&1; then
		echo "Accepted an invalid version: $version" >&2
		exit 1
	fi
	grep -q 'Invalid version:' "$work/update.log"
done

# Exercise a valid update on a copy, with a local archive in place of curl.
mkdir "$work/update"
cp "$dir/update.sh" "$dir/Makefile" "$dir/versions.mk" "$work/update/"
cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
while [ "$1" != -o ]; do
	shift
done
printf 'test archive\n' > "$2"
EOF
chmod +x "$work/bin/curl"
"$work/update/update.sh" LIBNET 1.2.3-rc1 >"$work/update.log"
grep -q '^LIBNET_VERSION *:= 1.2.3-rc1$' "$work/update/versions.mk"
checksum=$(printf 'test archive\n' | sha256sum | cut -d ' ' -f 1)
grep -q "^LIBNET_SHA256 *:= $checksum\$" "$work/update/versions.mk"

echo 'Static build tool checks PASS'
