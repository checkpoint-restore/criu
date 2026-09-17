#!/usr/bin/env python3

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import unittest.mock as mock


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "contrib/compression-benchmark"))
import cuda_migration  # noqa: E402
import podman_common as common  # noqa: E402


SOURCE = "GPU-00000000-0000-0000-0000-000000000001"
TARGET = "GPU-00000000-0000-0000-0000-000000000002"
OTHER = "GPU-00000000-0000-0000-0000-000000000003"
GPU_LIST = (f"0, {OTHER}, NVIDIA H100, 610.57.04, Disabled\n"
            f"1, {SOURCE}, NVIDIA H100, 610.57.04, Disabled\n"
            f"2, {TARGET}, NVIDIA H100, 610.57.04, Disabled\n")


def arguments(**changes):
    values = dict(accelerator="gpu", cuda_backends=["driver-api"],
                  criu_libdir="/plugins", tensor_parallel_size=1,
                  gpu_device="nvidia.com/gpu=all", cuda_visible_devices="0",
                  cuda_migrate_gpus=["1", "2"], env=[],
                  cuda_checkpoint_launch_job=True)
    values.update(changes)
    return SimpleNamespace(**values)


class MigrationTests(unittest.TestCase):
    def test_selected_pair_excludes_other_host_gpus_and_maps_unused_device(self):
        args = arguments()
        with mock.patch.object(cuda_migration, "command_output", return_value=GPU_LIST):
            cuda_migration.prepare(args)
        self.assertEqual(args.cuda_visible_devices, f"{SOURCE},{TARGET}")
        self.assertEqual(args.cuda_migration["source"]["uuid"], SOURCE)
        self.assertEqual(args.cuda_migration["target"]["uuid"], TARGET)
        self.assertEqual(args.cuda_migration["device_map"], f"{SOURCE}={TARGET},{TARGET}={SOURCE}")

    def test_full_uuid_selectors_support_reverse_migration(self):
        args = arguments(cuda_migrate_gpus=[TARGET, SOURCE])
        with mock.patch.object(cuda_migration, "command_output", return_value=GPU_LIST):
            cuda_migration.prepare(args)
        self.assertEqual(args.cuda_visible_devices, f"{TARGET},{SOURCE}")

    def test_aliases_of_same_physical_gpu_are_rejected(self):
        args = arguments(cuda_migrate_gpus=["1", SOURCE])
        with (
            mock.patch.object(cuda_migration, "command_output", return_value=GPU_LIST),
            self.assertRaisesRegex(RuntimeError, "two different physical GPUs"),
        ):
            cuda_migration.prepare(args)

    def test_conflicting_workload_configuration_is_rejected_before_probing(self):
        for changes in (
            {"tensor_parallel_size": 2}, {"accelerator": "cpu"},
            {"cuda_backends": None}, {"criu_libdir": None},
            {"cuda_visible_devices": "1"}, {"gpu_device": "nvidia.com/gpu=0"},
            {"env": ["CUDA_VISIBLE_DEVICES=0"]}, {"env": ["NVIDIA_VISIBLE_DEVICES"]},
        ):
            with (
                self.subTest(changes=changes),
                mock.patch.object(cuda_migration, "command_output") as probe,
                self.assertRaises(RuntimeError),
            ):
                cuda_migration.prepare(arguments(**changes))
            probe.assert_not_called()

    def test_mig_and_unsupported_job_driver_are_rejected(self):
        for output, message in (
            (GPU_LIST.replace("Disabled", "Enabled"), "MIG disabled"),
            (GPU_LIST.replace("610.57.04", "580.82.07"), "r610"),
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(cuda_migration, "command_output", return_value=output),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                cuda_migration.prepare(arguments())

    def test_observation_ignores_other_jobs_and_tracks_container_pids(self):
        with mock.patch.object(cuda_migration, "command_output", side_effect=[
            "HPID PID\n100 1\n101 42\n",
            f"101, {SOURCE}\n999, {TARGET}\n",
        ]):
            processes = cuda_migration.observe("sglang-test")
        self.assertEqual(processes, [
            {"host_pid": 101, "container_pid": 42, "gpu_uuids": [SOURCE]},
        ])
        cuda_migration.check_placement(processes, SOURCE)

    def test_placement_requires_cuda_workers_on_only_the_expected_gpu(self):
        for processes in ([], [
            {"host_pid": 101, "container_pid": 42, "gpu_uuids": [SOURCE]},
        ], [
            {"host_pid": 101, "container_pid": 42, "gpu_uuids": [SOURCE, TARGET]},
        ]):
            with self.subTest(processes=processes), self.assertRaises(RuntimeError):
                cuda_migration.check_placement(processes, TARGET)

    def test_replaced_cuda_worker_is_rejected(self):
        before = [{"host_pid": 101, "container_pid": 42, "gpu_uuids": [SOURCE]}]
        after = [{"host_pid": 201, "container_pid": 43, "gpu_uuids": [TARGET]}]
        with self.assertRaisesRegex(RuntimeError, "container PIDs changed"):
            cuda_migration.check_placement(after, TARGET, before)

    def test_wrapper_sets_gpu_view_even_if_runtime_discards_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_criu = Path(directory) / "fake criu"
            fake_criu.write_text('#!/bin/sh\nprintf "%s\\n" "$CUDA_VISIBLE_DEVICES" "$@"\n')
            fake_criu.chmod(0o700)
            benchmark = common.ServingBenchmark(None, "test")
            with mock.patch.object(common.shutil, "which", return_value=str(fake_criu)):
                wrapper = benchmark.ensure_no_default_config_wrapper(f"{SOURCE},{TARGET}")
            try:
                result = subprocess.run([str(Path(wrapper) / "criu"), "swrk", "3"],
                                        env={"PATH": os.defpath}, capture_output=True,
                                        text=True, check=True)
                self.assertEqual(result.stdout.splitlines(), [
                    f"{SOURCE},{TARGET}", "--no-default-config", "swrk", "3",
                ])
            finally:
                common.cleanup(benchmark)

    def test_mapping_is_restore_only_and_original_configuration_is_restored(self):
        original = ("log-level 4\nplugin-option cuda_plugin.device-map=old\n"
                    "plugin-option unrelated.value=kept\n")
        cfg = {"mode": "uncompressed", "block_size": 0, "cuda_backend": "driver-api",
               "criu_libdir": "/plugins", "cuda_device_map": f"{SOURCE}={TARGET},{TARGET}={SOURCE}"}
        benchmark = common.ServingBenchmark(None, "test")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runc.conf"
            path.write_text(original)
            try:
                for restore in (False, True, False):
                    benchmark.set_runc_conf_for_cfg(str(path), cfg, 1, restore=restore)
                    active = path.read_text()
                    self.assertIn("unrelated.value=kept", active)
                    self.assertNotIn("device-map=old", active)
                    self.assertEqual(active.count("cuda_plugin.device-map="), int(restore))
                    if restore:
                        self.assertIn(cfg["cuda_device_map"], active)
            finally:
                benchmark.restore_runc_conf()
            self.assertEqual(path.read_text(), original)


if __name__ == "__main__":
    unittest.main()
