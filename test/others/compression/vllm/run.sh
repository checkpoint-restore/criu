#!/bin/sh

set -eu

root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)

: "${VLLM_CPU_IMAGE:=vllm/vllm-openai-cpu:latest-x86_64}"
: "${VLLM_CPU_MODEL:=Qwen/Qwen2.5-0.5B-Instruct}"

if [ "$(id -u)" -ne 0 ]; then
	echo "compression/vllm: must run as root" >&2
	exit 1
fi

timeout --foreground --kill-after=60s 3600s python3 \
	"$root/contrib/compression-benchmark/podman-vllm.py" \
	--accelerator cpu \
	--image "$VLLM_CPU_IMAGE" \
	--model "$VLLM_CPU_MODEL" \
	--iterations 1 \
	--modes uncompressed lz4-page lz4-region \
	--region-sizes 65536 \
	--decompress-threads 4 \
	--archive-compression none \
	--cpu-kvcache-space 1 \
	--max-model-len 512 \
	--max-tokens 4 \
	--shm-size 4g \
	--wait-seconds 1200 \
	--request-timeout 300
