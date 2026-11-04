#!/bin/sh
#
# Check a CRIU binary built by `make static`: it is fully static, the
# optional features built from the bundled libraries are present, and so
# are the listed plugins.
#
# Usage: check-binary.sh BINARY [PLUGIN...]

set -eu

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 BINARY [PLUGIN...]" >&2
	exit 1
fi

binary=$1
shift

fail()
{
	echo "error: $binary: $*" >&2
	exit 1
}

# $1 is defined in the binary.
linked()
{
	nm "$binary" | grep -q " $1\$"
}

program_headers=$(readelf -l "$binary") || fail "cannot read ELF program headers"
dynamic_section=$(readelf -d "$binary") || fail "cannot read ELF dynamic section"

if printf '%s\n' "$program_headers" | grep -q INTERP; then
	fail "has an ELF interpreter; it is not fully static"
fi
if printf '%s\n' "$dynamic_section" | grep -q '(NEEDED)'; then
	fail "depends on shared libraries; it is not fully static"
fi

linked LZ4_compress_default || fail "was built without LZ4 compression support"
linked nft_run_cmd_from_buffer || fail "was built without nftables support"
linked is_selinux_enabled || fail "was built without SELinux support"

for plugin; do
	linked "${plugin}_plugin_desc" || fail "was built without the $plugin plugin"
done

echo "$binary: OK"
