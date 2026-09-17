"""Physical GPU placement checks for the SGLang checkpoint/restore benchmark."""

import csv
import json
import os
import subprocess


def command_output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(command)} failed: {(result.stderr or result.stdout).strip()}"
        )
    return result.stdout


def prepare(args):
    """Select a two-GPU CUDA view and a complete UUID swap for TP=1."""
    if args.accelerator != "gpu" or not args.cuda_backends or not args.criu_libdir:
        raise RuntimeError("--cuda-migrate-gpus requires GPU, --cuda-backends and --criu-libdir")
    if args.tensor_parallel_size != 1:
        raise RuntimeError("--cuda-migrate-gpus requires --tensor-parallel-size=1")
    if args.gpu_device != "nvidia.com/gpu=all":
        raise RuntimeError("--cuda-migrate-gpus requires --gpu-device=nvidia.com/gpu=all")
    if args.cuda_visible_devices != "0":
        raise RuntimeError("--cuda-migrate-gpus sets CUDA visibility; omit --cuda-visible-devices")
    reserved = {"CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER", "NVIDIA_VISIBLE_DEVICES"}
    if any(entry.split("=", 1)[0] in reserved for entry in args.env):
        raise RuntimeError("--cuda-migrate-gpus cannot be combined with GPU visibility overrides in --env")

    output = command_output([
        "nvidia-smi", "--query-gpu=index,uuid,name,driver_version,mig.mode.current",
        "--format=csv,noheader,nounits",
    ])
    devices = []
    for row in csv.reader(output.splitlines()):
        if len(row) != 5:
            raise RuntimeError(f"unexpected nvidia-smi GPU row: {row!r}")
        devices.append(dict(zip(
            ("index", "uuid", "name", "driver_version", "mig_mode"),
            (value.strip() for value in row),
        )))

    selected = []
    for selector in args.cuda_migrate_gpus:
        matches = [gpu for gpu in devices if selector in (gpu["index"], gpu["uuid"])]
        if len(matches) != 1:
            raise RuntimeError(f"GPU {selector!r} must be an nvidia-smi index or full GPU UUID")
        selected.append(matches[0])
    source, target = selected
    if source["uuid"] == target["uuid"]:
        raise RuntimeError("GPU migration requires two different physical GPUs")
    if source["name"] != target["name"]:
        raise RuntimeError("GPU migration test requires GPUs of the same model")
    for gpu in selected:
        if gpu["mig_mode"].lower() == "enabled":
            raise RuntimeError("GPU migration test requires MIG disabled")
        minimum_driver = 610 if args.cuda_checkpoint_launch_job else 580
        if int(gpu["driver_version"].split(".", 1)[0]) < minimum_driver:
            raise RuntimeError(f"this GPU migration configuration requires driver r{minimum_driver} or newer")

    source_uuid, target_uuid = source["uuid"], target["uuid"]
    # Both GPUs remain accessible through the unchanged OCI specification.
    # The unused second CUDA device must be mapped too: the plugin records
    # the complete CUDA-visible inventory, not just devices with allocations.
    args.cuda_visible_devices = f"{source_uuid},{target_uuid}"
    args.cuda_migration = {
        "source": source,
        "target": target,
        "device_map": f"{source_uuid}={target_uuid},{target_uuid}={source_uuid}",
    }


def observe(container):
    """Join host NVML placement to stable container PIDs, excluding other jobs."""
    output = command_output(["podman", "top", container, "hpid", "pid"])
    host_to_container = {}
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) != 2 or not all(field.isdecimal() for field in fields):
            raise RuntimeError(f"unexpected podman top row: {line!r}")
        host_to_container[int(fields[0])] = int(fields[1])

    output = command_output([
        "nvidia-smi", "--query-compute-apps=pid,gpu_uuid",
        "--format=csv,noheader,nounits",
    ])
    processes = {}
    for row in csv.reader(output.splitlines()):
        if len(row) != 2 or not row[0].strip().isdecimal():
            raise RuntimeError(f"unexpected nvidia-smi process row: {row!r}")
        host_pid = int(row[0])
        if host_pid not in host_to_container:
            continue
        process = processes.setdefault(host_pid, {
            "host_pid": host_pid,
            "container_pid": host_to_container[host_pid],
            "gpu_uuids": [],
        })
        uuid = row[1].strip()
        if uuid not in process["gpu_uuids"]:
            process["gpu_uuids"].append(uuid)
    for process in processes.values():
        process["gpu_uuids"].sort()
    return sorted(processes.values(), key=lambda process: process["container_pid"])


def check_placement(processes, expected_uuid, before=None):
    if not processes:
        raise RuntimeError("no CUDA processes from the benchmark container found in nvidia-smi")
    for process in processes:
        if process["gpu_uuids"] != [expected_uuid]:
            raise RuntimeError(
                f"container PID {process['container_pid']} uses {process['gpu_uuids']}; "
                f"expected only {expected_uuid}"
            )
    if before is not None:
        old_pids = {process["container_pid"] for process in before}
        new_pids = {process["container_pid"] for process in processes}
        if old_pids != new_pids:
            raise RuntimeError(
                f"CUDA worker container PIDs changed across restore: {sorted(old_pids)} "
                f"-> {sorted(new_pids)}"
            )


def verify(container, migration, directory, phase, before=None):
    processes = observe(container)
    expected = migration["source" if phase == "before" else "target"]["uuid"]
    # Preserve the actual placement even when it fails validation.
    with open(os.path.join(directory, f"gpu-placement-{phase}.json"), "w") as output:
        json.dump({"expected_uuid": expected, "processes": processes}, output, indent=2)
    check_placement(processes, expected, before)
    pids = ",".join(str(process["container_pid"]) for process in processes)
    print(f"  GPU migration {phase}: container CUDA PIDs {pids} on {expected}", flush=True)
    return processes
