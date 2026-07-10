#!/usr/bin/env python3
"""
Podman SGLang Checkpoint/Restore Benchmark

Starts an SGLang container with Podman, validates inference, checkpoints it with
Podman, removes it, restores it with Podman, and validates inference again.

This benchmarks Podman's container checkpoint/restore path while varying CRIU
memory-page compression through /etc/criu/runc.conf. Podman's own checkpoint
archive compression is kept at "none" by default so the reported archive size
reflects CRIU image size rather than tar-level gzip/zstd compression.

Example:
  sudo HF_TOKEN=... python3 contrib/compression-benchmark/podman-sglang.py \\
       --model Qwen/Qwen3-0.6B -n 3 \\
       --modes uncompressed lz4-page lz4-region

CPU-only example (requires an SGLang CPU image):
  sudo python3 contrib/compression-benchmark/podman-sglang.py \\
       --accelerator cpu --image sglang-cpu:latest
"""

import os
import sys

_BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

import podman_common as common  # noqa: E402


class SglangAdapter:
    key = "sglang"
    display_name = "SGLang"
    heading = "SGLANG"
    default_container_name = "sglang-criu-bench"
    temp_prefix = "podman-sglang-bench-"

    @staticmethod
    def add_image_arguments(parser):
        parser.add_argument(
            "--image",
            help="Container image (default: lmsysorg/sglang:latest for GPU; "
                 "required for CPU)",
        )

    @staticmethod
    def add_model_arguments(parser):
        parser.add_argument(
            "--sglang-model-arg",
            choices=["model", "model-path"],
            default="model-path",
            help="SGLang launch flag used for the model path",
        )

    @staticmethod
    def add_resource_arguments(parser):
        parser.add_argument("--mem-fraction-static", type=float, default=0.35)
        parser.add_argument("--max-total-tokens", type=int, default=8192)
        parser.add_argument("--context-length", type=int, default=8192)
        parser.add_argument(
            "--tensor-parallel-size",
            type=int,
            default=1,
            help="SGLang tensor-parallel ranks (default: 1)",
        )

    @staticmethod
    def add_request_arguments(parser):
        parser.add_argument(
            "--enable-thinking",
            action="store_true",
            help="Do not add chat_template_kwargs.enable_thinking=false",
        )

    @staticmethod
    def add_server_arguments(parser):
        parser.add_argument(
            "--sglang-arg",
            action="append",
            default=[],
            help="Extra raw argument appended to sglang.launch_server",
        )

    @staticmethod
    def normalize_args(parser, args):
        if args.image is not None:
            return
        if args.accelerator == "cpu":
            parser.error(
                "--image is required for CPU mode; build the SGLang "
                "docker/xeon.Dockerfile image first"
            )
        args.image = "lmsysorg/sglang:latest"

    @staticmethod
    def prepare_args(args):
        if not args.enable_thinking:
            extra = dict(args.chat_extra_json or {})
            extra.setdefault(
                "chat_template_kwargs", {"enable_thinking": False}
            )
            args.chat_extra_json = extra

    @staticmethod
    def cpu_podman_args(args):
        return [
            "--security-opt", "seccomp=unconfined",
            "--cap-add", "SYS_NICE",
            "--env", "SGLANG_USE_CPU_ENGINE=1",
        ]

    @staticmethod
    def server_argv(args):
        command = [
            args.image,
            "python3", "-m", "sglang.launch_server",
            f"--{args.sglang_model_arg}", args.model,
            "--host", "0.0.0.0",
            "--port", str(args.port),
            "--max-total-tokens", str(args.max_total_tokens),
            "--context-length", str(args.context_length),
            "--tp", str(args.tensor_parallel_size),
        ]
        if args.accelerator == "gpu":
            command += ["--mem-fraction-static", str(args.mem_fraction_static)]
        else:
            command += ["--device", "cpu", "--disable-overlap-schedule"]
        command += args.sglang_arg
        return command

    @staticmethod
    def server_summary(args):
        return f"model-arg={args.sglang_model_arg}"


_benchmark = common.ServingBenchmark(SglangAdapter(), __doc__)

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
