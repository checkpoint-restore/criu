#!/usr/bin/env python3

import contextlib
import errno
import importlib.util
import io
import os
from pathlib import Path
import signal
import sys
import tarfile
from types import SimpleNamespace
import unittest
import unittest.mock as mock
import warnings


ROOT = Path(__file__).resolve().parents[4]
BENCHMARK = ROOT / "contrib" / "compression-benchmark"


def load_script(name):
    path = BENCHMARK / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PodmanConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vllm = load_script("podman-vllm.py")
        cls.sglang = load_script("podman-sglang.py")
        cls.common = cls.vllm.common
        cls.main = load_script("main.py")
        cls.region_cache = load_script("region-cache.py")

    def test_serving_frontends_share_code_not_runtime_state(self):
        self.assertIs(self.vllm.common, self.sglang.common)
        self.assertIsNot(self.vllm._benchmark, self.sglang._benchmark)
        self.assertIsNot(self.vllm._benchmark.state,
                         self.sglang._benchmark.state)

    def test_shared_serving_format_helpers_have_explicit_names(self):
        self.assertEqual(self.common.format_bytes(1048576), "1.0 MB")
        self.assertEqual(self.common.format_duration(1000), "1.0 ms")

    def test_decompression_thread_labels_distinguish_default_and_auto(self):
        for module in (self.main, self.common):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.decompress_threads_label(None),
                                 "default (serial)")
                self.assertEqual(module.decompress_threads_label(0), "auto")
                self.assertEqual(module.decompress_threads_label(1), "1")

    def test_default_server_url_follows_port(self):
        self.assertEqual(
            self.common.server_base_url(30001, None),
            "http://127.0.0.1:30001",
        )
        self.assertEqual(
            self.common.server_base_url(30001, "http://server.example:80"),
            "http://server.example:80",
        )

    def test_random_bytes_are_stable_without_random_randbytes(self):
        import random

        rng = random.Random(42)
        self.assertEqual(
            self.main.workload._random_bytes(rng, 16).hex(),
            "9d79b1a37f31801cd11a6706fb40d6bd",
        )

    def test_workload_start_timeout_scales_with_mapping_size(self):
        rate = self.main.WORKLOAD_START_MIN_RATE

        self.assertEqual(self.main.workload_start_timeout(256 * 1024 * 1024),
                         30)
        self.assertEqual(self.main.workload_start_timeout(rate * 30), 30)
        self.assertEqual(self.main.workload_start_timeout(rate * 30 + 1), 31)
        self.assertEqual(self.main.workload_start_timeout(32 * 1024 ** 3),
                         512)

    def test_explicit_auto_decompression_is_preserved(self):
        self.assertEqual(self.main.decompress_threads_args(None), [])
        self.assertEqual(
            self.main.decompress_threads_args(0),
            ["--decompress-threads", "0"],
        )

        cfg = {"mode": "lz4-page", "region_size": 0}
        self.assertEqual(
            self.common.compression_config_lines(cfg, 1, None), ["compress"]
        )
        self.assertEqual(
            self.common.compression_config_lines(cfg, 1, 0),
            ["compress", "decompress-threads 0"],
        )

    def test_podman_environment_uses_no_default_config_wrapper(self):
        args = SimpleNamespace(criu_libdir=None)
        for module in (self.vllm, self.sglang):
            with (
                self.subTest(module=module.__name__),
                mock.patch.dict(os.environ, {
                    "PATH": "/usr/bin",
                    "CRIU_CONFIG_FILE": "/tmp/ambient.conf",
                }, clear=True),
                mock.patch.object(
                    module._benchmark, "ensure_no_default_config_wrapper",
                    return_value="/tmp/criu-wrapper",
                ),
            ):
                env = module.podman_env(args)
                self.assertNotIn("CRIU_CONFIG_FILE", env)
                self.assertEqual(
                    env["PATH"], "/tmp/criu-wrapper" + os.pathsep + "/usr/bin"
                )

    def test_criu_wrapper_disables_default_configuration(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                wrapper_dir = os.path.join(d, "wrapper")
                os.mkdir(wrapper_dir)
                module._benchmark.state.criu_wrapper_dir = None
                with (
                    mock.patch.object(module.shutil, "which",
                                      return_value="/opt/criu build/criu"),
                    mock.patch.object(module.tempfile, "mkdtemp",
                                      return_value=wrapper_dir),
                ):
                    self.assertEqual(
                        module._benchmark.ensure_no_default_config_wrapper(),
                        wrapper_dir,
                    )
                wrapper = os.path.join(wrapper_dir, "criu")
                with open(wrapper) as source:
                    contents = source.read()
                self.assertIn("--no-default-config", contents)
                self.assertIn("'/opt/criu build/criu'", contents)
                self.assertTrue(os.access(wrapper, os.X_OK))
                module._benchmark.state.tempdirs.discard(wrapper_dir)
                module._benchmark.state.criu_wrapper_dir = None

    def test_failed_criu_wrapper_setup_remains_tracked_for_cleanup(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                wrapper_dir = os.path.join(d, "wrapper")
                os.mkdir(wrapper_dir)
                module._benchmark.state.criu_wrapper_dir = None
                with (
                    mock.patch.object(module.shutil, "which",
                                      return_value="/usr/bin/criu"),
                    mock.patch.object(module.tempfile, "mkdtemp",
                                      return_value=wrapper_dir),
                    mock.patch.object(module.os, "open",
                                      side_effect=OSError("injected failure")),
                    self.assertRaisesRegex(OSError, "injected failure"),
                ):
                    module._benchmark.ensure_no_default_config_wrapper()
                self.assertIn(wrapper_dir, module._benchmark.state.tempdirs)
                module._benchmark.state.tempdirs.discard(wrapper_dir)

    def test_region_cache_marker_write_is_atomic_and_cleans_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ready")
            self.region_cache.atomic_write_text(path, "123\n")
            with open(path) as marker:
                self.assertEqual(marker.read(), "123\n")

            failed_path = os.path.join(d, "failed")
            with (
                mock.patch.object(
                    self.region_cache.os, "replace",
                    side_effect=OSError("injected rename failure"),
                ),
                self.assertRaisesRegex(OSError, "injected rename failure"),
            ):
                self.region_cache.atomic_write_text(failed_path, "456\n")
            self.assertEqual(
                list(Path(d).glob("failed.tmp.*")), [],
            )

    def test_duplicate_compression_configurations_are_rejected(self):
        cases = (
            (self.main, ["--modes", "uncompressed", "uncompressed"]),
            (self.vllm, ["--modes", "uncompressed", "uncompressed"]),
            (self.sglang, ["--region-sizes", "65536", "65536"]),
        )
        for module, arguments in cases:
            with (
                self.subTest(module=module.__name__),
                mock.patch.object(module.sys, "argv", [module.__file__, *arguments]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                module.main()
            self.assertEqual(raised.exception.code, 2)

    def test_checkpoint_archive_inventory_member_is_extracted(self):
        import tempfile

        payload = b"inventory payload\x00"
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                archive = os.path.join(d, "checkpoint.tar.gz")
                with tarfile.open(archive, "w:gz") as output:
                    info = tarfile.TarInfo("checkpoint/inventory.img")
                    info.size = len(payload)
                    output.addfile(info, io.BytesIO(payload))
                self.assertEqual(
                    module.inventory_bytes_from_archive(archive), payload
                )

    def test_checkpoint_archive_inventory_is_decoded(self):
        import tempfile

        lib = str(ROOT / "lib")
        if lib not in sys.path:
            sys.path.insert(0, lib)
        try:
            from pycriu import images
        except ImportError as error:
            self.skipTest(f"generated pycriu bindings are unavailable: {error}")
            return
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            payload = images.dumps({
                "magic": "INVENTORY",
                "entries": [{
                    "img_version": 1,
                    "compress": 2,
                    "compress_region_size": 65536,
                }],
            })
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                archive = os.path.join(d, "checkpoint.tar")
                with tarfile.open(archive, "w") as output:
                    info = tarfile.TarInfo("checkpoint/inventory.img")
                    info.size = len(payload)
                    output.addfile(info, io.BytesIO(payload))
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    entry = module.inventory_entry_from_archive(archive)
                self.assertEqual(entry["compress"], 2)

    def test_checkpoint_archive_mode_and_region_are_verified(self):
        configurations = (
            ({"mode": "uncompressed", "region_size": 0}, {}, 0),
            ({"mode": "lz4-page", "region_size": 0}, {"compress": 1}, 1),
            ({"mode": "lz4-region", "region_size": 65536}, {
                "compress": 2, "compress_region_size": 65536,
            }, 2),
        )
        for module in (self.vllm, self.sglang):
            for cfg, entry, expected in configurations:
                with (
                    self.subTest(module=module.__name__, cfg=cfg),
                    mock.patch.object(
                        module.common, "inventory_entry_from_archive",
                        return_value=entry,
                    ),
                ):
                    self.assertEqual(
                        module.verify_archive_compression("archive", cfg),
                        expected,
                    )

            with (
                self.subTest(module=module.__name__, mismatch=True),
                mock.patch.object(
                    module.common, "inventory_entry_from_archive",
                    return_value={"compress": 1},
                ),
                self.assertRaisesRegex(RuntimeError, "does not match"),
            ):
                module.verify_archive_compression(
                    "archive", {"mode": "uncompressed", "region_size": 0}
                )

            with (
                self.subTest(module=module.__name__, region_mismatch=True),
                mock.patch.object(
                    module.common, "inventory_entry_from_archive",
                    return_value={
                        "compress": 2, "compress_region_size": 131072,
                    },
                ),
                self.assertRaisesRegex(RuntimeError, "region does not match"),
            ):
                module.verify_archive_compression(
                    "archive", {"mode": "lz4-region", "region_size": 65536}
                )

    def test_uncompressed_mode_removes_ambient_compression(self):
        source = """manage-cgroups ignore
compress
compress-region=65536
compress_acceleration 2
decompress-threads 4
# keep this comment
log-file /tmp/criu.log
# BEGIN criu-compression-benchmark
compress
# END criu-compression-benchmark
"""
        expected = """manage-cgroups ignore
# keep this comment
log-file /tmp/criu.log"""
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    module.strip_compression_runc_options(source), expected
                )
                self.assertEqual(
                    module.compression_config_lines(
                        {"mode": "uncompressed", "region_size": 0}, 2, 4
                    ),
                    [],
                )

    def test_uncompressed_config_is_applied_and_original_is_restored(self):
        import tempfile

        original = "manage-cgroups ignore\ncompress\ndecompress-threads 8\n"
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "runc.conf")
                with open(path, "w") as f:
                    f.write(original)
                module.set_runc_conf_for_cfg(
                    path, {"mode": "uncompressed", "region_size": 0}, 1, 0
                )
                with open(path) as f:
                    active = f.read()
                self.assertNotIn("compress", active)
                self.assertNotIn("decompress-threads", active)
                module.restore_runc_conf()
                with open(path) as f:
                    self.assertEqual(f.read(), original)

    def test_missing_runc_config_is_removed_after_restore(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "runc.conf")
                module.set_runc_conf_for_cfg(
                    path, {"mode": "lz4-page", "region_size": 0}, 1, 0
                )
                self.assertTrue(os.path.isfile(path))
                self.assertEqual(os.stat(path).st_mode & 0o7777, 0o600)
                module.restore_runc_conf()
                self.assertFalse(os.path.exists(path))

    def test_runc_config_lock_prevents_concurrent_benchmarks(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runc.conf")
            with open(path, "w") as f:
                f.write("manage-cgroups ignore\n")
            self.vllm.set_runc_conf_for_cfg(
                path, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "another.*benchmark"):
                    self.sglang.set_runc_conf_for_cfg(
                        path, {"mode": "lz4-page", "region_size": 0}, 1, 0
                    )
            finally:
                self.vllm.restore_runc_conf()

    def test_runc_config_symlink_and_crash_recovery(self):
        import tempfile

        original = "manage-cgroups ignore\n"
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "real.conf")
            path = os.path.join(d, "runc.conf")
            with open(target, "w") as f:
                f.write(original)
            os.symlink("real.conf", path)

            self.vllm.set_runc_conf_for_cfg(
                path, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            self.assertTrue(os.path.islink(path))

            # Simulate SIGKILL: the lock is released by the kernel but the
            # recovery file and modified config remain. The next frontend
            # must restore the original before starting its own transaction.
            self.vllm._benchmark.release_runc_conf_lock()
            self.vllm._benchmark.state.original_runc_conf = (
                self.common._RUNC_CONF_UNSET
            )
            self.sglang.set_runc_conf_for_cfg(
                path, {"mode": "uncompressed", "region_size": 0}, 1, 0
            )
            self.sglang.restore_runc_conf()

            self.assertTrue(os.path.islink(path))
            with open(target) as f:
                self.assertEqual(f.read(), original)

    def test_runc_config_recovers_pending_atomic_write(self):
        import tempfile

        original = "manage-cgroups ignore\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runc.conf")
            with open(path, "w") as f:
                f.write(original)

            real_write = self.vllm.write_file

            def stop_after_rename(*args, **kwargs):
                real_write(*args, **kwargs)
                raise RuntimeError("simulated power loss after rename")

            with mock.patch.object(
                self.vllm.common, "write_file", side_effect=stop_after_rename
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated power loss"):
                    self.vllm.set_runc_conf_for_cfg(
                        path, {"mode": "lz4-page", "region_size": 0}, 1, 0
                    )
            with open(path) as f:
                self.assertIn("compress", f.read())

            # Simulate process death: only the kernel-owned file lock goes
            # away. The durable journal still describes the pending rename.
            self.vllm._benchmark.release_runc_conf_lock()
            self.vllm._benchmark.state.original_runc_conf = (
                self.common._RUNC_CONF_UNSET
            )
            self.sglang.set_runc_conf_for_cfg(
                path, {"mode": "uncompressed", "region_size": 0}, 1, 0
            )
            self.sglang.restore_runc_conf()
            with open(path) as f:
                self.assertEqual(f.read(), original)

    def test_runc_config_recovers_after_restore_before_journal_delete(self):
        import tempfile

        original = "manage-cgroups ignore\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runc.conf")
            with open(path, "w") as f:
                f.write(original)
            self.vllm.set_runc_conf_for_cfg(
                path, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            state_path = self.vllm._benchmark.state.runc_conf_state_path
            real_unlink = self.vllm.os.unlink

            def stop_before_journal_delete(name):
                if name == state_path:
                    raise OSError(errno.EIO, "simulated power loss")
                return real_unlink(name)

            with mock.patch.object(
                self.vllm.os, "unlink", side_effect=stop_before_journal_delete
            ):
                with self.assertRaisesRegex(OSError, "simulated power loss"):
                    self.vllm.restore_runc_conf()
            with open(path) as f:
                self.assertEqual(f.read(), original)
            self.assertTrue(os.path.exists(state_path))

            self.sglang.set_runc_conf_for_cfg(
                path, {"mode": "uncompressed", "region_size": 0}, 1, 0
            )
            self.sglang.restore_runc_conf()
            with open(path) as f:
                self.assertEqual(f.read(), original)

    def test_runc_config_symlink_alias_uses_target_lock(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "real.conf")
            alias = os.path.join(d, "runc.conf")
            with open(target, "w") as f:
                f.write("manage-cgroups ignore\n")
            os.symlink("real.conf", alias)

            self.vllm.set_runc_conf_for_cfg(
                alias, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "another.*benchmark"):
                    self.sglang.set_runc_conf_for_cfg(
                        target, {"mode": "uncompressed", "region_size": 0},
                        1, 0
                    )
            finally:
                self.vllm.restore_runc_conf()

    def test_stale_recovery_refuses_external_edit(self):
        import tempfile

        original = "manage-cgroups ignore\n"
        administrator_edit = "manage-cgroups strict\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runc.conf")
            with open(path, "w") as f:
                f.write(original)

            self.vllm.set_runc_conf_for_cfg(
                path, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            state_path = (os.path.realpath(path) +
                          ".compression-benchmark.lock.state")
            self.vllm._benchmark.release_runc_conf_lock()
            self.vllm._benchmark.state.original_runc_conf = (
                self.common._RUNC_CONF_UNSET
            )
            with open(path, "w") as f:
                f.write(administrator_edit)

            with self.assertRaisesRegex(RuntimeError, "changed outside"):
                self.sglang.set_runc_conf_for_cfg(
                    path, {"mode": "uncompressed", "region_size": 0}, 1, 0
                )
            with open(path) as f:
                self.assertEqual(f.read(), administrator_edit)
            self.assertTrue(os.path.exists(state_path))

    def test_stale_recovery_refuses_external_metadata_edit(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runc.conf")
            with open(path, "w") as f:
                f.write("manage-cgroups ignore\n")

            self.vllm.set_runc_conf_for_cfg(
                path, {"mode": "lz4-page", "region_size": 0}, 1, 0
            )
            state_path = (os.path.realpath(path) +
                          ".compression-benchmark.lock.state")
            self.vllm._benchmark.release_runc_conf_lock()
            self.vllm._benchmark.state.original_runc_conf = (
                self.common._RUNC_CONF_UNSET
            )
            metadata = os.stat(path)
            os.utime(path, ns=(metadata.st_atime_ns,
                               metadata.st_mtime_ns + 1_000_000_000))

            with self.assertRaisesRegex(RuntimeError, "changed outside"):
                self.sglang.set_runc_conf_for_cfg(
                    path, {"mode": "uncompressed", "region_size": 0},
                    1, 0
                )
            self.assertEqual(os.stat(path).st_mtime_ns,
                             metadata.st_mtime_ns + 1_000_000_000)
            self.assertTrue(os.path.exists(state_path))

    def test_runc_config_atomic_write_preserves_metadata(self):
        import tempfile

        if not hasattr(os, "setxattr"):
            self.skipTest("extended attributes are unavailable")
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "runc.conf")
                with open(path, "w") as f:
                    f.write("manage-cgroups ignore\n")
                os.chmod(path, 0o600)
                os.utime(path, ns=(1_700_000_000_000_000_000,
                                   1_700_000_001_000_000_000))
                try:
                    os.setxattr(path, "user.criu-benchmark", b"preserve-me")
                except OSError as e:
                    if e.errno in (errno.ENOTSUP, errno.EPERM, errno.EACCES):
                        self.skipTest("test filesystem does not support user xattrs")
                    raise
                before = os.stat(path)

                module.set_runc_conf_for_cfg(
                    path, {"mode": "lz4-page", "region_size": 0}, 1, 0
                )
                active = os.stat(path)
                self.assertEqual(active.st_mode & 0o7777, 0o600)
                self.assertEqual(active.st_uid, before.st_uid)
                self.assertEqual(active.st_gid, before.st_gid)
                self.assertEqual(active.st_mtime_ns, before.st_mtime_ns)
                self.assertEqual(
                    os.getxattr(path, "user.criu-benchmark"), b"preserve-me"
                )
                module.restore_runc_conf()
                restored = os.stat(path)
                self.assertEqual(restored.st_mode & 0o7777, 0o600)
                self.assertEqual(restored.st_atime_ns, before.st_atime_ns)
                self.assertEqual(restored.st_mtime_ns, before.st_mtime_ns)
                self.assertEqual(
                    os.getxattr(path, "user.criu-benchmark"), b"preserve-me"
                )

    def test_runc_config_restore_preserves_original_atime(self):
        import tempfile

        original_atime = 946_684_800_123_456_789
        original_mtime = 1_700_000_001_000_000_000
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "runc.conf")
                with open(path, "w") as output:
                    output.write("manage-cgroups ignore\n")
                os.utime(path, ns=(original_atime, original_mtime))
                before = os.stat(path)

                module.set_runc_conf_for_cfg(
                    path, {"mode": "lz4-page", "region_size": 0}, 1, 0
                )
                module.restore_runc_conf()

                restored = os.stat(path)
                self.assertEqual(restored.st_atime_ns, before.st_atime_ns)
                self.assertEqual(restored.st_mtime_ns, before.st_mtime_ns)

    def test_json_config_redacts_environment_values(self):
        args = SimpleNamespace(
            env=["PUBLIC_NAME", "SECRET=value"],
            run_arg=["--env=RUN_SECRET=run-value", "--env", "PAIR=pair-value",
                     "--annotation=test"],
        )
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__):
                encoded = str(module.json_config(args))
                self.assertNotIn("value", encoded)
                self.assertIn("SECRET=<redacted>", encoded)
                self.assertIn("--env=RUN_SECRET=<redacted>", encoded)
                self.assertIn("PAIR=<redacted>", encoded)

    def test_run_arg_environment_forms_are_rejected_and_redacted(self):
        dangerous = [
            "--env", "--env=SECRET=value", "-e", "-e=SECRET=value",
            "-eSECRET=value",
        ]
        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__):
                for item in dangerous:
                    self.assertTrue(module.run_arg_sets_environment(item))
                self.assertFalse(
                    module.run_arg_sets_environment("--annotation=test=value")
                )
                formatted = module.format_cmd([
                    "podman", "run", "--env=SECRET=value",
                    "-eOTHER=other-value", "image",
                ])
                self.assertNotIn("value", formatted)
                self.assertIn("--env=SECRET=<redacted>", formatted)
                self.assertIn("-eOTHER=<redacted>", formatted)

    def test_cpu_commands_do_not_request_a_gpu_or_expose_hf_token(self):
        common = {
            "accelerator": "cpu",
            "security_opt": "label=disable",
            "shm_size": "4g",
            "hf_cache": "/tmp/hf-cache",
            "env": [],
            "volume": [],
            "run_arg": [],
            "ulimit": [],
            "gpu_device": "nvidia.com/gpu=all",
            "cuda_visible_devices": "0",
            "image": "cpu-image",
            "model": "tiny-model",
            "port": 30000,
        }
        vllm_args = SimpleNamespace(
            **common,
            cpu_kvcache_space=4,
            vllm_entrypoint="image",
            max_model_len=128,
            tensor_parallel_size=1,
            gpu_memory_utilization=0.35,
            dtype="auto",
            served_model_name=None,
            vllm_arg=[],
        )
        sglang_args = SimpleNamespace(
            **common,
            sglang_model_arg="model-path",
            max_total_tokens=128,
            context_length=128,
            tensor_parallel_size=1,
            mem_fraction_static=0.35,
            sglang_arg=[],
        )

        old_token = os.environ.get("HF_TOKEN")
        old_hub_token = os.environ.get("HUGGING_FACE_HUB_TOKEN")
        os.environ["HF_TOKEN"] = "must-not-appear"
        os.environ["HUGGING_FACE_HUB_TOKEN"] = "also-must-not-appear"
        try:
            commands = [
                self.vllm.build_container_cmd("vllm-test", vllm_args),
                self.sglang.build_container_cmd("sglang-test", sglang_args),
            ]
        finally:
            if old_token is None:
                del os.environ["HF_TOKEN"]
            else:
                os.environ["HF_TOKEN"] = old_token
            if old_hub_token is None:
                del os.environ["HUGGING_FACE_HUB_TOKEN"]
            else:
                os.environ["HUGGING_FACE_HUB_TOKEN"] = old_hub_token

        for command in commands:
            with self.subTest(command=command):
                joined = " ".join(command)
                self.assertNotIn("must-not-appear", joined)
                self.assertNotIn("also-must-not-appear", joined)
                self.assertNotIn("nvidia.com/gpu", joined)
                self.assertNotIn("CUDA_VISIBLE_DEVICES", joined)
                self.assertIn("HF_TOKEN", command)

    def test_health_wait_fails_immediately_for_exited_container(self):
        for module in (self.vllm, self.sglang):
            with (
                self.subTest(module=module.__name__),
                mock.patch.object(
                    module.common.urllib.request, "urlopen",
                    side_effect=module.common.urllib.error.URLError("not ready"),
                ),
                mock.patch.object(module.common, "container_exit_code",
                                  return_value=17),
                mock.patch.object(module.common, "container_diagnostics",
                                  return_value="diagnostics"),
                self.assertRaisesRegex(RuntimeError, "exited with status 17"),
            ):
                module.common.wait_health(
                    "http://127.0.0.1:30000", "/health", 1200,
                    "failed-container", module._benchmark.adapter.display_name,
                )

    @staticmethod
    def trial_args():
        return SimpleNamespace(
            container_name="framework-test",
            archive_compression="none",
            served_model_name=None,
            model="tiny-model",
            warmup_requests=0,
            base_url="http://127.0.0.1:30000",
            prompt="deterministic prompt",
            max_tokens=4,
            temperature=0,
            seed=42,
            request_timeout=10,
            chat_extra_json=None,
            keep_running=False,
        )

    def run_mocked_trial(self, module, workdir, responses, keep_running=False):
        events = []

        def start(*_args):
            events.append("start")

        def chat(*_args):
            events.append("chat")
            return 10, responses.pop(0)

        def checkpoint(*_args):
            events.append("checkpoint")
            return 20, "checkpoint stats"

        def verify(*_args):
            events.append("verify")
            return 0

        def remove(*_args, **_kwargs):
            events.append("remove")
            return module.subprocess.CompletedProcess([], 0, "", "")

        def restore(*_args):
            events.append("restore")
            return 30, "restore stats"

        benchmark = module._benchmark
        with (
            mock.patch.object(benchmark, "start_container", side_effect=start),
            mock.patch.object(benchmark, "chat_once", side_effect=chat),
            mock.patch.object(benchmark, "checkpoint_container",
                              side_effect=checkpoint),
            mock.patch.object(module.common, "verify_archive_compression",
                              side_effect=verify),
            mock.patch.object(module.common, "run_cmd", side_effect=remove),
            mock.patch.object(benchmark, "restore_container", side_effect=restore),
            mock.patch.object(module.common.os.path, "getsize", return_value=1234),
        ):
            result = module.run_trial(
                {"mode": "uncompressed", "region_size": 0},
                workdir,
                self.trial_args(),
                1,
                keep_running,
            )
        return result, events

    def test_mocked_framework_restore_validates_identical_response(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                result, events = self.run_mocked_trial(
                    module, d, ["same response", "same response"]
                )
                self.assertTrue(result["valid"])
                self.assertEqual(result["archive_size"], 1234)
                self.assertEqual(
                    events,
                    ["start", "chat", "checkpoint", "verify", "remove",
                     "restore", "chat", "remove"],
                )

    def test_mocked_framework_restore_rejects_changed_response(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(
                    RuntimeError, "validation response changed"
                ):
                    self.run_mocked_trial(
                        module, d, ["before restore", "after restore"]
                    )

    def test_keep_running_retains_only_requested_trial(self):
        import tempfile

        for module in (self.vllm, self.sglang):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as d:
                result, events = self.run_mocked_trial(
                    module, d, ["same response", "same response"], True
                )
                self.assertIsNotNone(result["container_name"])
                self.assertEqual(
                    events,
                    ["start", "chat", "checkpoint", "verify", "remove",
                     "restore", "chat"],
                )

    def test_signal_handlers_defer_cleanup_and_are_not_reentrant(self):
        # The serving frontends keep their state on the shared benchmark
        # object; main and region-cache keep a module-level _runtime.
        handlers = (
            (self.vllm, self.vllm._benchmark.state,
             self.vllm._benchmark.signal_handler, self.vllm.cleanup),
            (self.sglang, self.sglang._benchmark.state,
             self.sglang._benchmark.signal_handler, self.sglang.cleanup),
            (self.main, self.main._runtime,
             self.main._sighandler, self.main._cleanup),
            (self.region_cache, self.region_cache._runtime,
             self.region_cache.on_signal, self.region_cache.cleanup_pids),
        )
        for module, state, handler, cleanup in handlers:
            with (
                self.subTest(module=module.__name__),
                mock.patch.object(module.signal, "signal"),
                mock.patch.object(module, cleanup.__name__) as cleanup_mock,
            ):
                state.received_signal = None
                with self.assertRaises(SystemExit) as raised:
                    handler(signal.SIGINT, None)
                self.assertEqual(raised.exception.code, 128 + signal.SIGINT)
                cleanup_mock.assert_not_called()
                handler(signal.SIGTERM, None)
                cleanup_mock.assert_not_called()
                state.received_signal = None

    def test_region_cache_wait_detects_child_exit(self):
        proc = mock.Mock()
        proc.poll.return_value = 17
        with (
            mock.patch.object(self.region_cache.os.path, "exists",
                              return_value=False),
            self.assertRaisesRegex(
                self.region_cache.TrialError, "exited with status 17"
            ),
        ):
            self.region_cache.wait_for_path(
                "/missing-readiness-file", timeout=1, proc=proc
            )

    def test_region_cache_images_require_reused_lz4_region(self):
        page_size = self.region_cache.PAGE_SIZE
        start = 0x100000
        pre_entries = [{
            "vaddr": start,
            "nr_pages": 4,
            "flags": self.region_cache.PE_PRESENT,
            "region_pages": 4,
            "compressed_size": [100],
        }]
        final_entries = [
            {
                "vaddr": start + index * page_size,
                "nr_pages": 1,
                "flags": (self.region_cache.PE_PRESENT if index % 2 == 0
                          else self.region_cache.PE_PARENT),
            }
            for index in range(4)
        ]

        evidence = self.region_cache.analyze_partial_region_reads(
            pre_entries, final_entries, start, 4 * page_size,
            4 * page_size,
        )
        self.assertEqual(evidence["partial_parent_slices"], 2)
        self.assertEqual(evidence["reused_lz4_regions"], 1)
        self.assertEqual(evidence["max_slices_per_region"], 2)

        pre_entries[0]["compressed_size"] = [4 * page_size]
        with self.assertRaisesRegex(
                self.region_cache.TrialError, "no LZ4-compressed region"):
            self.region_cache.analyze_partial_region_reads(
                pre_entries, final_entries, start, 4 * page_size,
                4 * page_size,
            )

        pre_entries[0]["nr_pages"] = 2
        pre_entries[0]["region_pages"] = 2
        pre_entries[0]["compressed_size"] = [100]
        with self.assertRaisesRegex(
                self.region_cache.TrialError, "repeated partial reads"):
            self.region_cache.analyze_partial_region_reads(
                pre_entries, final_entries[:2], start, 2 * page_size,
                2 * page_size,
            )

    def test_region_cache_readiness_failure_reaps_child(self):
        import tempfile

        proc = mock.Mock(pid=12345)
        proc.poll.return_value = None
        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.object(self.region_cache.subprocess, "Popen",
                              return_value=proc),
            mock.patch.object(
                self.region_cache, "wait_for_path",
                side_effect=self.region_cache.TrialError("not ready"),
            ),
            self.assertRaisesRegex(self.region_cache.TrialError, "not ready"),
        ):
            self.region_cache.start_workload(self.region_cache.PAGE_SIZE, d)
        proc.kill.assert_called_once_with()
        proc.wait.assert_called_once_with()
        self.assertNotIn(proc.pid, self.region_cache._runtime.active_pids)

    def test_region_cache_failure_kills_restored_workload(self):
        import tempfile

        proc = mock.Mock(pid=12345)
        proc.wait.return_value = 0
        restored_pid = 23456

        def publish_restore_pid(cmd, cwd=None):
            del cwd
            if "restore" in cmd:
                pidfile = cmd[cmd.index("--pidfile") + 1]
                with open(pidfile, "w") as output:
                    output.write(f"{restored_pid}\n")
            return 0.01

        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.object(
                self.region_cache, "start_workload",
                return_value=(proc, proc.pid, 0x100000,
                              os.path.join(d, "dirty"),
                              os.path.join(d, "checksum")),
            ),
            mock.patch.object(self.region_cache, "run_cmd",
                              side_effect=publish_restore_pid),
            mock.patch.object(self.region_cache, "signal_and_wait"),
            mock.patch.object(
                self.region_cache, "validate_region_cache_images",
                return_value={"reused_lz4_regions": 1},
            ),
            mock.patch.object(self.region_cache, "expected_checksum",
                              return_value="expected"),
            mock.patch.object(self.region_cache.os, "kill") as kill_mock,
        ):
            result = self.region_cache.run_trial(
                "/usr/bin/criu", self.region_cache.PAGE_SIZE,
                self.region_cache.PAGE_SIZE, "expected", d, False,
            )

        self.assertFalse(result["ok"])
        kill_mock.assert_any_call(restored_pid, signal.SIGKILL)
        self.assertNotIn(
            restored_pid, self.region_cache._runtime.active_pids
        )


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_script("main.py")

    def test_storage_ratio_is_normalized_by_logical_pages(self):
        template = {
            "total_size": 100,
            "frozen_us": 1,
            "memdump_us": 1,
            "memwrite_us": 1,
            "dump_wall_us": 1,
            "restore_us": 1,
            "restore_wall_us": 1,
            "valid": True,
        }
        baseline = dict(template, pages_size=100, logical_pages=10)
        baseline["pages_written"] = 10
        compressed = dict(template, pages_size=60, logical_pages=5,
                          pages_written=5)
        results = {"Uncompressed": [baseline], "Compressed": [compressed]}

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.main.report("mixed", 1, results,
                             ["Uncompressed", "Compressed"])
        self.assertIn("1.200x", output.getvalue())
        self.assertEqual(self.main.PAGE_SIZE, os.sysconf("SC_PAGE_SIZE"))

    def test_shared_pages_are_included_in_logical_throughput(self):
        trials = [{
            "logical_pages": 12,
            "pages_written": 4,
            "shpages_written": 8,
            "restore_us": 1_000_000,
        }]
        expected = 12 * self.main.PAGE_SIZE / 1048576
        self.assertEqual(
            self.main.median_throughput(trials, "restore_us"),
            f"{expected:.0f} MB/s",
        )

    def test_shared_pages_are_excluded_from_memwrite_throughput(self):
        trials = [{
            "logical_pages": 12,
            "pages_written": 4,
            "shpages_written": 8,
            "memwrite_us": 1_000_000,
        }]
        expected = 4 * self.main.PAGE_SIZE / 1048576
        self.assertEqual(
            self.main.median_throughput(
                trials, "memwrite_us", "pages_written"
            ),
            f"{expected:.0f} MB/s",
        )

    def test_requested_cache_drop_reports_sync_failure(self):
        failed = self.main.subprocess.CompletedProcess(
            ["sync"], 1, stdout="", stderr="sync diagnostic"
        )
        with mock.patch.object(self.main.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "sync diagnostic"):
                self.main.drop_caches()


if __name__ == "__main__":
    unittest.main()
