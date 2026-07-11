#!/usr/bin/env python3
"""
Podman vLLM Checkpoint/Restore Benchmark

Starts a vLLM container with Podman, validates inference, checkpoints it with
Podman, removes it, restores it with Podman, and validates inference again.

This benchmarks Podman's container checkpoint/restore path while varying CRIU
memory-page compression through /etc/criu/runc.conf. Podman's own checkpoint
archive compression is kept at "none" by default so the reported archive size
reflects CRIU image size rather than tar-level gzip/zstd compression.

Example:
  sudo HF_TOKEN=... python3 contrib/compression-benchmark/podman-vllm.py \\
       --model Qwen/Qwen3-0.6B -n 3 \\
       --modes uncompressed lz4-page lz4-region

CPU-only example:
  sudo python3 contrib/compression-benchmark/podman-vllm.py \\
       --accelerator cpu --model facebook/opt-125m
"""

import os
import platform
import sys

_BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

import podman_common as common  # noqa: E402


class VllmAdapter:
    key = "vllm"
    display_name = "vLLM"
    heading = "VLLM"
    default_container_name = "vllm-criu-bench"
    temp_prefix = "podman-vllm-bench-"

    @staticmethod
    def add_image_arguments(parser):
        parser.add_argument(
            "--image",
            help="Container image (default: official GPU or CPU vLLM "
                 "OpenAI image selected by --accelerator)",
        )
        parser.add_argument(
            "--vllm-entrypoint",
            choices=["image", "serve", "module"],
            default="image",
            help="Use the image entrypoint (recommended), or override it "
                 "with vllm serve/the legacy Python module",
        )

    @staticmethod
    def add_model_arguments(parser):
        return None

    @staticmethod
    def add_resource_arguments(parser):
        parser.add_argument("--gpu-memory-utilization", type=float, default=0.35)
        parser.add_argument(
            "--cpu-kvcache-space",
            type=int,
            default=4,
            help="vLLM CPU KV-cache space in GiB (default: 4)",
        )
        parser.add_argument("--max-model-len", type=int, default=8192)
        parser.add_argument("--tensor-parallel-size", type=int, default=1)
        parser.add_argument(
            "--dtype",
            default="auto",
            help="vLLM dtype argument; use an empty string to omit",
        )

    @staticmethod
    def add_request_arguments(parser):
        return None

    @staticmethod
    def add_server_arguments(parser):
        parser.add_argument(
            "--vllm-arg",
            action="append",
            default=[],
            help="Extra raw argument appended to the vLLM server command",
        )

    @staticmethod
    def normalize_args(parser, args):
        if args.image is not None:
            return
        if args.accelerator == "gpu":
            args.image = "vllm/vllm-openai:latest"
        elif platform.machine() in ("aarch64", "arm64"):
            args.image = "vllm/vllm-openai-cpu:latest-arm64"
        else:
            args.image = "vllm/vllm-openai-cpu:latest-x86_64"

    @staticmethod
    def prepare_args(args):
        if args.dtype == "":
            args.dtype = None

    @staticmethod
    def cpu_podman_args(args):
        return [
            "--security-opt", "seccomp=unconfined",
            "--cap-add", "SYS_NICE",
            "--env", f"VLLM_CPU_KVCACHE_SPACE={args.cpu_kvcache_space}",
        ]

    @staticmethod
    def server_argv(args):
        command = []
        if args.vllm_entrypoint == "serve":
            command += ["--entrypoint", "vllm", args.image, "serve"]
        elif args.vllm_entrypoint == "module":
            command += [
                "--entrypoint", "python3", args.image, "-m",
                "vllm.entrypoints.openai.api_server",
            ]
        else:
            command.append(args.image)

        command += [
            "--model", args.model,
            "--host", "0.0.0.0",
            "--port", str(args.port),
            "--max-model-len", str(args.max_model_len),
            "--tensor-parallel-size", str(args.tensor_parallel_size),
        ]
        if args.accelerator == "gpu":
            command += [
                "--gpu-memory-utilization", str(args.gpu_memory_utilization)
            ]
        if args.dtype:
            command += ["--dtype", args.dtype]
        if args.served_model_name:
            command += ["--served-model-name", args.served_model_name]
        command += args.vllm_arg
        return command

    @staticmethod
    def server_summary(args):
        return f"entrypoint={args.vllm_entrypoint}"


_benchmark = common.ServingBenchmark(VllmAdapter(), __doc__)

# Keep useful import-level helpers available to callers and focused tests.
format_bytes = common.format_bytes
format_duration = common.format_duration
inventory_bytes_from_archive = common.inventory_bytes_from_archive
inventory_entry_from_archive = common.inventory_entry_from_archive
verify_archive_compression = common.verify_archive_compression
strip_compression_runc_options = common.strip_compression_runc_options
compression_config_lines = common.compression_config_lines
json_config = common.json_config
format_cmd = common.format_cmd
run_arg_sets_environment = common.run_arg_sets_environment
write_file = common.write_file
os = common.os
shutil = common.shutil
signal = common.signal
subprocess = common.subprocess
tempfile = common.tempfile
urllib = common.urllib

main = _benchmark.main
podman_env = _benchmark.podman_env
set_runc_conf_for_cfg = _benchmark.set_runc_conf_for_cfg
restore_runc_conf = _benchmark.restore_runc_conf
build_container_cmd = _benchmark.build_container_cmd
run_trial = _benchmark.run_trial
cleanup = _benchmark.cleanup


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"Error: {error}")
