#!/bin/sh

set -eu

root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)

: "${SGLANG_CPU_IMAGE:?SGLANG_CPU_IMAGE must name an image built from SGLang docker/xeon.Dockerfile}"
: "${SGLANG_CPU_MODEL:=Qwen/Qwen2.5-0.5B-Instruct}"

if [ "$(id -u)" -ne 0 ]; then
	echo "compression/sglang: must run as root" >&2
	exit 1
fi

timeout --foreground --kill-after=60s 3600s python3 \
	"$root/contrib/compression-benchmark/podman-sglang.py" \
	--accelerator cpu \
	--image "$SGLANG_CPU_IMAGE" \
	--model "$SGLANG_CPU_MODEL" \
	--iterations 1 \
	--modes uncompressed lz4-page lz4-region \
	--region-sizes 65536 \
	--decompress-threads 4 \
	--archive-compression none \
	--max-total-tokens 512 \
	--context-length 512 \
	--max-tokens 4 \
	--shm-size 4g \
	--wait-seconds 1200 \
	--request-timeout 300
