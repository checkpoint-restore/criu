#!/usr/bin/env python3
"""
Podman SGLang Checkpoint/Restore Benchmark

Starts an SGLang container with Podman, validates inference, checkpoints it with
Podman, removes it, restores it with Podman, and validates inference again.

GPU runs enable SGLang's memory saver by default. Before checkpoint the driver
pauses generation and releases SGLang-managed GPU allocations; after restore it
resumes those allocations and generation. CUDA backend comparisons also launch
the server in a CUDA checkpoint job, which establishes the shared job identity
required for CUDA IPC checkpointing on r610 and later drivers. Memory release
does not replace that identity. Pass --disable-memory-saver only for diagnostic
comparisons.

This benchmarks Podman's container checkpoint/restore path while varying CRIU
memory-page compression through /etc/criu/runc.conf. Podman's own checkpoint
archive compression is kept at "none" by default so the reported archive size
reflects CRIU image size rather than tar-level gzip/zstd compression.

Example:
  sudo HF_TOKEN=... python3 contrib/compression-benchmark/podman-sglang.py \\
       --model Qwen/Qwen3-0.6B -n 3 \\
       --modes uncompressed lz4-block --block-sizes 4096 262144

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
        parser.add_argument("--model-revision", help="Immutable Hugging Face model commit")
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
            "--cuda-backends", nargs="+",
            choices=["driver-api", "cuda-checkpoint"],
            help="Compare explicit CUDA backends in alternating trial order",
        )
        parser.add_argument(
            "--disable-memory-saver",
            dest="memory_saver",
            action="store_false",
            default=True,
            help="Checkpoint live CUDA allocations instead of releasing "
                 "SGLang GPU memory first (not recommended)",
        )
        launch_job = parser.add_mutually_exclusive_group()
        launch_job.add_argument(
            "--cuda-checkpoint-launch-job",
            action="store_true",
            default=None,
            help="Launch SGLang through cuda-checkpoint --launch-job so all "
                 "CUDA workers inherit one checkpoint job file "
                 "(default with --cuda-backends; requires r610 or later)",
        )
        launch_job.add_argument(
            "--no-cuda-checkpoint-launch-job",
            dest="cuda_checkpoint_launch_job",
            action="store_false",
            help="Do not create a CUDA checkpoint job; only for workloads "
                 "that do not require CUDA IPC checkpointing",
        )
        parser.add_argument(
            "--cuda-checkpoint-binary",
            default="cuda-checkpoint",
            help="Host cuda-checkpoint binary mounted into the container "
                 "(default: resolve cuda-checkpoint from PATH)",
        )
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
        if args.cuda_backends:
            if args.accelerator != "gpu" or not args.criu_libdir:
                raise RuntimeError("--cuda-backends requires GPU and --criu-libdir")
            if len(set(args.cuda_backends)) != len(args.cuda_backends):
                raise RuntimeError("--cuda-backends must not contain duplicates")
            if args.json and os.path.exists(args.json):
                raise RuntimeError(f"Results already exist: {args.json}")
        if args.cuda_checkpoint_launch_job is None:
            args.cuda_checkpoint_launch_job = bool(args.cuda_backends)
        if not args.enable_thinking:
            extra = dict(args.chat_extra_json or {})
            extra.setdefault(
                "chat_template_kwargs", {"enable_thinking": False}
            )
            args.chat_extra_json = extra
        if args.cuda_checkpoint_launch_job:
            if args.accelerator != "gpu":
                raise RuntimeError(
                    "--cuda-checkpoint-launch-job requires --accelerator gpu"
                )
            binary = common.shutil.which(args.cuda_checkpoint_binary)
            if not binary:
                raise RuntimeError(
                    "cuda-checkpoint executable not found: "
                    f"{args.cuda_checkpoint_binary}"
                )
            args.cuda_checkpoint_binary = os.path.abspath(binary)

    @staticmethod
    def extra_podman_args(args):
        if not getattr(args, "cuda_checkpoint_launch_job", False):
            return []
        return [
            "--volume",
            f"{args.cuda_checkpoint_binary}:/usr/local/bin/cuda-checkpoint:ro",
        ]

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
        ]
        if getattr(args, "cuda_checkpoint_launch_job", False):
            command += ["/usr/local/bin/cuda-checkpoint", "--launch-job"]
        command += [
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
            if args.memory_saver and "--enable-memory-saver" not in args.sglang_arg:
                command.append("--enable-memory-saver")
        else:
            command += ["--device", "cpu", "--disable-overlap-schedule"]
        if getattr(args, "model_revision", None):
            command += ["--revision", args.model_revision]
        command += args.sglang_arg
        return command

    @staticmethod
    def _memory_control(args, operations):
        if getattr(args, "accelerator", None) != "gpu" or not getattr(
                args, "memory_saver", False):
            return
        for endpoint, payload in operations:
            print(f"  SGLang memory saver: {endpoint}", flush=True)
            try:
                common.http_json(
                    "POST",
                    f"{args.base_url.rstrip('/')}/{endpoint}",
                    payload,
                    args.request_timeout,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"SGLang memory-saver request {endpoint} failed: {exc}"
                ) from exc

    @classmethod
    def before_checkpoint(cls, args):
        cls._memory_control(args, [
            ("pause_generation", {"mode": "abort"}),
            ("release_memory_occupation", {}),
        ])

    @classmethod
    def after_restore(cls, args):
        cls._memory_control(args, [
            ("resume_memory_occupation", {}),
            ("continue_generation", {}),
        ])

    @staticmethod
    def server_summary(args):
        memory_saver = "on" if args.memory_saver else "off"
        launch_job = "on" if args.cuda_checkpoint_launch_job else "off"
        return (f"model-arg={args.sglang_model_arg}, "
                f"memory-saver={memory_saver}, launch-job={launch_job}")


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
