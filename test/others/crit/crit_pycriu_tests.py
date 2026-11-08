#!/usr/bin/env python3
"""Unit tests for pycriu image serialization (pb2dict, magic, images) and CRIT CLI."""

import base64
import binascii
import copy
import io
import json
import os
import quopri
import shutil
import socket
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pycriu
from crit import __main__ as crit_main
from pycriu.images import images, magic, pb, pb2dict


class Pb2DictTestCase(unittest.TestCase):
    """Unit tests for lib/pycriu/images/pb2dict.py."""

    def test_nested_messages_and_unset_optional_fields(self):
        entry = pb.core_entry()
        entry.mtype = pb.core_entry.X86_64
        entry.tc.task_state = 1  # Alive
        entry.tc.exit_code = 0
        entry.tc.personality = 0
        entry.tc.flags = 0x402000
        entry.tc.blk_sigset = 0x100000000
        entry.tc.comm = "criu-worker"
        entry.ids.vm_id = 10
        entry.ids.files_id = 20
        entry.ids.fs_id = 30
        entry.ids.sighand_id = 40

        d = pb2dict.pb2dict(entry, pretty=False)
        self.assertEqual(d["mtype"], "X86_64")
        self.assertEqual(d["tc"]["comm"], "criu-worker")
        self.assertEqual(d["tc"]["task_state"], 1)
        self.assertEqual(d["tc"]["blk_sigset"], 0x100000000)
        self.assertEqual(d["ids"]["vm_id"], 10)
        # Unset optional fields should not appear in dictionary output
        self.assertNotIn("thread_core", d)
        self.assertNotIn("timers", d["tc"])
        self.assertNotIn("pid_ns_id", d["ids"])

        restored = pb.core_entry()
        pb2dict.dict2pb(d, restored)
        self.assertEqual(restored.SerializeToString(), entry.SerializeToString())
        self.assertFalse(restored.HasField("thread_core"))
        self.assertFalse(restored.ids.HasField("pid_ns_id"))

    def test_repeated_fields_and_empty_repeated_submessage(self):
        # Scalar repeated field (threads)
        ps = pb.pstree_entry()
        ps.pid = 100
        ps.ppid = 1
        ps.pgid = 100
        ps.sid = 100
        ps.threads.extend([100, 101, 102])

        ps_dict = pb2dict.pb2dict(ps)
        self.assertEqual(ps_dict["threads"], [100, 101, 102])

        ps_restored = pb.pstree_entry()
        pb2dict.dict2pb(ps_dict, ps_restored)
        self.assertEqual(list(ps_restored.threads), [100, 101, 102])

        # Optional message with empty repeated field (inventory_entry.plugins_entry)
        inv_dict = {
            "img_version": 2,
            "plugins_entry": {},
        }
        inv = pb.inventory_entry()
        pb2dict.dict2pb(inv_dict, inv)
        self.assertTrue(inv.HasField("plugins_entry"))
        self.assertEqual(len(inv.plugins_entry.plugins), 0)

        roundtrip_inv = pb2dict.pb2dict(inv)
        self.assertIn("plugins_entry", roundtrip_inv)
        self.assertEqual(roundtrip_inv["plugins_entry"], {})

        # Non-empty plugins list inside plugins_entry
        inv_with_plugins_dict = {
            "img_version": 2,
            "plugins_entry": {"plugins": ["cuda.so", "amdgpu.so"]},
        }
        inv2 = pb.inventory_entry()
        pb2dict.dict2pb(inv_with_plugins_dict, inv2)
        self.assertEqual(list(inv2.plugins_entry.plugins), ["cuda.so", "amdgpu.so"])
        self.assertEqual(
            pb2dict.pb2dict(inv2)["plugins_entry"]["plugins"],
            ["cuda.so", "amdgpu.so"],
        )

    def test_bytes_base64_and_utf8_strings(self):
        raw_bytes = b"\x00\x01\xfe\xffbinary-payload\x00"
        utf8_name = "policy-\u03b1\u03b2\u03b3"

        aa = pb.apparmor_entry()
        ns = aa.namespaces.add()
        ns.name = "root-ns"
        pol = ns.policies.add()
        pol.name = utf8_name
        pol.blob = raw_bytes

        d = pb2dict.pb2dict(aa)
        pol_dict = d["namespaces"][0]["policies"][0]
        self.assertEqual(pol_dict["name"], utf8_name)
        self.assertEqual(
            pol_dict["blob"],
            base64.encodebytes(raw_bytes).decode("utf8"),
        )

        restored = pb.apparmor_entry()
        pb2dict.dict2pb(d, restored)
        self.assertEqual(restored.namespaces[0].policies[0].name, utf8_name)
        self.assertEqual(restored.namespaces[0].policies[0].blob, raw_bytes)

        # Invalid base64 payload should raise binascii.Error
        bad_dict = {
            "namespaces": [
                {
                    "name": "root-ns",
                    "policies": [{"name": "bad", "blob": "!!!not_valid_base64!!!"}],
                }
            ]
        }
        with self.assertRaises(binascii.Error):
            pb2dict.dict2pb(bad_dict, pb.apparmor_entry())

    def test_custom_conv_unix_name_quopri(self):
        # unix_sk_entry.name has [(criu).conv = "unix_name"] which uses quopri
        abstract_name = b"\x00/tmp/dbus-socket"
        usk = pb.unix_sk_entry()
        usk.id = 1
        usk.ino = 12345
        usk.type = socket.SOCK_STREAM
        usk.state = 1
        usk.flags = 0x802
        usk.uflags = 0
        usk.backlog = 0
        usk.peer = 0
        usk.fown.uid = 0
        usk.fown.euid = 0
        usk.fown.signum = 0
        usk.fown.pid_type = 0
        usk.fown.pid = 0
        usk.opts.so_sndbuf = 212992
        usk.opts.so_rcvbuf = 212992
        usk.opts.so_snd_tmo_sec = 0
        usk.opts.so_snd_tmo_usec = 0
        usk.opts.so_rcv_tmo_sec = 0
        usk.opts.so_rcv_tmo_usec = 0
        usk.name = abstract_name

        d = pb2dict.pb2dict(usk, pretty=True)
        self.assertEqual(d["name"], quopri.encodestring(abstract_name).decode("utf-8"))
        self.assertEqual(d["type"], "STREAM")
        self.assertEqual(d["state"], "ESTABLISHED")
        self.assertEqual(d["flags"], "0x802")

        restored = pb.unix_sk_entry()
        pb2dict.dict2pb(d, restored)
        self.assertEqual(restored.name, abstract_name)
        self.assertEqual(restored.type, socket.SOCK_STREAM)
        self.assertEqual(restored.state, 1)
        self.assertEqual(restored.flags, 0x802)

    def test_pretty_field_handlers_hex_flags_dev_and_ip(self):
        # 1. VMA entry: hex addresses and mmap.prot / mmap.flags / mmap.status bitmasks
        vma = pb.vma_entry()
        vma.start = 0x7FFF0000
        vma.end = 0x7FFF1000
        vma.pgoff = 0
        vma.shmid = 0
        vma.prot = 0x1 | 0x2  # PROT_READ | PROT_WRITE
        vma.flags = 0x02 | 0x20 | 0x800000  # MAP_PRIVATE | MAP_ANON | unknown bit
        vma.status = (1 << 0) | (1 << 1)  # VMA_AREA_REGULAR | VMA_AREA_STACK
        vma.fd = -1

        vma_pretty = pb2dict.pb2dict(vma, pretty=True)
        self.assertEqual(vma_pretty["start"], "0x7fff0000")
        self.assertEqual(vma_pretty["end"], "0x7fff1000")
        self.assertEqual(vma_pretty["prot"], "PROT_READ | PROT_WRITE")
        self.assertEqual(vma_pretty["flags"], "MAP_PRIVATE | MAP_ANON | 0x800000")
        self.assertEqual(vma_pretty["status"], "VMA_AREA_REGULAR | VMA_AREA_STACK")

        vma_restored = pb.vma_entry()
        pb2dict.dict2pb(vma_pretty, vma_restored)
        self.assertEqual(vma_restored.SerializeToString(), vma.SerializeToString())

        # 2. Ghost file entry: new and old device encoding (dev and odev)
        gf = pb.ghost_file_entry()
        gf.uid = 1000
        gf.gid = 1000
        gf.mode = 0o100644
        # New kdev format: major=8, minor=1 -> (8 << 20) | 1
        gf.dev = (8 << 20) | 1
        # Old dev format: major=1, minor=3 -> os.makedev(1, 3)
        gf.rdev = os.makedev(1, 3)

        gf_pretty = pb2dict.pb2dict(gf, pretty=True)
        self.assertEqual(gf_pretty["dev"], "8:1")
        self.assertEqual(gf_pretty["rdev"], "1:3")

        gf_restored = pb.ghost_file_entry()
        pb2dict.dict2pb(gf_pretty, gf_restored)
        self.assertEqual(gf_restored.dev, gf.dev)
        self.assertEqual(gf_restored.rdev, gf.rdev)

        # 3. Inet socket entry: IPv4 and IPv6 addresses
        isk4 = pb.inet_sk_entry()
        isk4.id = 1
        isk4.ino = 100
        isk4.family = socket.AF_INET
        isk4.type = socket.SOCK_STREAM
        isk4.proto = socket.IPPROTO_TCP
        isk4.state = 10  # LISTEN
        isk4.src_port = 8080
        isk4.dst_port = 0
        isk4.flags = 0
        isk4.backlog = 128
        isk4.src_addr.append(struct.unpack("I", socket.inet_pton(socket.AF_INET, "127.0.0.1"))[0])
        isk4.dst_addr.append(struct.unpack("I", socket.inet_pton(socket.AF_INET, "0.0.0.0"))[0])
        isk4.fown.uid = 0
        isk4.fown.euid = 0
        isk4.fown.signum = 0
        isk4.fown.pid_type = 0
        isk4.fown.pid = 0
        isk4.opts.so_sndbuf = 16384
        isk4.opts.so_rcvbuf = 87380
        isk4.opts.so_snd_tmo_sec = 0
        isk4.opts.so_snd_tmo_usec = 0
        isk4.opts.so_rcv_tmo_sec = 0
        isk4.opts.so_rcv_tmo_usec = 0

        isk4_pretty = pb2dict.pb2dict(isk4, pretty=True)
        self.assertEqual(isk4_pretty["family"], "INET")
        self.assertEqual(isk4_pretty["proto"], "TCP")
        self.assertEqual(isk4_pretty["state"], "LISTEN")
        self.assertEqual(isk4_pretty["src_addr"], ["127.0.0.1"])
        self.assertEqual(isk4_pretty["dst_addr"], ["0.0.0.0"])

        isk4_restored = pb.inet_sk_entry()
        pb2dict.dict2pb(isk4_pretty, isk4_restored)
        self.assertEqual(isk4_restored.SerializeToString(), isk4.SerializeToString())

        # IPv6 address roundtrip
        isk6 = pb.inet_sk_entry()
        isk6.CopyFrom(isk4)
        isk6.family = socket.AF_INET6
        del isk6.src_addr[:]
        isk6.src_addr.extend(struct.unpack("IIII", socket.inet_pton(socket.AF_INET6, "::1")))

        isk6_pretty = pb2dict.pb2dict(isk6, pretty=True)
        self.assertEqual(isk6_pretty["family"], "INET6")
        self.assertEqual(isk6_pretty["src_addr"], ["::1"])

        isk6_restored = pb.inet_sk_entry()
        pb2dict.dict2pb(isk6_pretty, isk6_restored)
        self.assertEqual(isk6_restored.SerializeToString(), isk6.SerializeToString())

    def test_enum_casting_and_invalid_enum_error(self):
        fd = pb.fdinfo_entry()
        pb2dict.dict2pb({"id": 1, "flags": 0, "type": "REG", "fd": 3}, fd)
        self.assertEqual(fd.type, pb.REG)
        self.assertEqual(pb2dict.pb2dict(fd)["type"], "REG")

        # Invalid enum string name or unknown integer raises AttributeError
        with self.assertRaises(AttributeError):
            pb2dict.dict2pb({"id": 1, "flags": 0, "type": "NOT_A_VALID_FD_TYPE", "fd": 3}, pb.fdinfo_entry())
        with self.assertRaises(AttributeError):
            pb2dict.dict2pb({"id": 1, "flags": 0, "type": 999999, "fd": 3}, pb.fdinfo_entry())


class MagicAndImagesTestCase(unittest.TestCase):
    """Unit tests for lib/pycriu/images/magic.py and lib/pycriu/images/images.py."""

    def test_magic_table_consistency(self):
        expected_magics = [
            "INVENTORY",
            "IMG_COMMON",
            "IMG_SERVICE",
            "CORE",
            "IDS",
            "FDINFO",
            "REG_FILES",
            "PSTREE",
            "PAGEMAP",
            "MM",
            "STATS",
            "IRMAP_CACHE",
            "GHOST_FILE",
            "PIPES_DATA",
            "TCP_STREAM",
        ]
        for name in expected_magics:
            self.assertIn(name, magic.by_name)
            val = magic.by_name[name]
            self.assertIsInstance(val, int)
            self.assertGreater(val, 1)
            self.assertEqual(magic.by_val[val], name)

        # RAW (0x0) and V1 (1) magics must be excluded from lookup tables
        self.assertNotIn(0, magic.by_val)
        self.assertNotIn(1, magic.by_val)
        for name, val in magic.by_name.items():
            self.assertEqual(magic.by_val[val], name)

    def test_header_magics_v1_0_common_and_service(self):
        # 1. INVENTORY uses v1.0 single 32-bit magic header
        inv_img = {"magic": "INVENTORY", "entries": [{"img_version": 2}]}
        inv_raw = images.dumps(inv_img)
        (first_magic,) = struct.unpack("i", inv_raw[:4])
        self.assertEqual(first_magic, magic.by_name["INVENTORY"])
        self.assertEqual(images.loads(inv_raw), inv_img)

        # 2. PSTREE uses v1.1 IMG_COMMON + PSTREE magic header
        ps_img = {
            "magic": "PSTREE",
            "entries": [{"pid": 1, "ppid": 0, "pgid": 1, "sid": 1, "threads": [1]}],
        }
        ps_raw = images.dumps(ps_img)
        m_common, m_pstree = struct.unpack("ii", ps_raw[:8])
        self.assertEqual(m_common, magic.by_name["IMG_COMMON"])
        self.assertEqual(m_pstree, magic.by_name["PSTREE"])
        self.assertEqual(images.loads(ps_raw), ps_img)

        # 3. STATS uses v1.1 IMG_SERVICE + STATS magic header
        stats_img = {
            "magic": "STATS",
            "entries": [
                {
                    "dump": {
                        "freezing_time": 10,
                        "frozen_time": 20,
                        "memdump_time": 30,
                        "memwrite_time": 40,
                        "pages_scanned": 100,
                        "pages_skipped_parent": 0,
                        "pages_written": 50,
                        "pages_lazy": 0,
                    }
                }
            ],
        }
        stats_raw = images.dumps(stats_img)
        m_service, m_stats = struct.unpack("ii", stats_raw[:8])
        self.assertEqual(m_service, magic.by_name["IMG_SERVICE"])
        self.assertEqual(m_stats, magic.by_name["STATS"])
        self.assertEqual(images.loads(stats_raw), stats_img)

    def test_pagemap_and_extra_payload_handlers(self):
        # Pagemap image (1 pagemap_head + 2 pagemap_entry records -> info count == 2)
        pm_img = {
            "magic": "PAGEMAP",
            "entries": [
                {"pages_id": 1},
                {"vaddr": 0x400000, "compat_nr_pages": 2, "nr_pages": 2, "flags": 4},
                {"vaddr": 0x402000, "compat_nr_pages": 1, "nr_pages": 1, "flags": 4},
            ],
        }
        pm_raw = images.dumps(pm_img)
        self.assertEqual(images.loads(pm_raw), pm_img)
        self.assertEqual(images.info(io.BytesIO(pm_raw)), {"magic": "PAGEMAP", "count": 2})

        # Pipes data image (extra_handler with binary payload)
        payload = b"hello pipe world!\n"
        pd_img = {
            "magic": "PIPES_DATA",
            "entries": [
                {
                    "pipe_id": 7,
                    "bytes": len(payload),
                    "extra": base64.encodebytes(payload).decode("utf-8"),
                }
            ],
        }
        pd_raw = images.dumps(copy.deepcopy(pd_img))
        self.assertEqual(images.load(io.BytesIO(pd_raw), no_payload=False), pd_img)

        # With no_payload=True, extra payload is replaced by human-readable size
        pd_nopl = images.load(io.BytesIO(pd_raw), no_payload=True)
        self.assertEqual(pd_nopl["entries"][0]["extra"], "... <%dB>" % len(payload))

        # Standard entry_handler.count via images.info()
        rf_img = {
            "magic": "REG_FILES",
            "entries": [
                {
                    "id": 1,
                    "flags": 0,
                    "pos": 0,
                    "fown": {"uid": 0, "euid": 0, "signum": 0, "pid_type": 0, "pid": 0},
                    "name": "/tmp/a",
                },
                {
                    "id": 2,
                    "flags": 0,
                    "pos": 0,
                    "fown": {"uid": 0, "euid": 0, "signum": 0, "pid_type": 0, "pid": 0},
                    "name": "/tmp/b",
                },
            ],
        }
        rf_raw = images.dumps(rf_img)
        self.assertEqual(images.info(io.BytesIO(rf_raw)), {"magic": "REG_FILES", "count": 2})

        # Ghost file handler (single entry followed by raw file content)
        ghost_data = b"ghost-file-contents-12345"
        gf_img = {
            "magic": "GHOST_FILE",
            "entries": [
                {
                    "uid": 0,
                    "gid": 0,
                    "mode": 0o100644,
                    "extra": base64.encodebytes(ghost_data).decode("utf-8"),
                }
            ],
        }
        gf_raw = images.dumps(copy.deepcopy(gf_img))
        self.assertEqual(images.load(io.BytesIO(gf_raw), no_payload=False), gf_img)
        gf_nopl = images.load(io.BytesIO(gf_raw), no_payload=True)
        self.assertNotIn("extra", gf_nopl["entries"][0])

    def test_corrupted_truncated_and_unknown_magic_headers(self):
        # 1. Unknown first magic raises MagicException with .magic set
        bad_first = struct.pack("ii", 0x13572468, 0)
        with self.assertRaises(images.MagicException) as ctx:
            images.loads(bad_first)
        self.assertEqual(ctx.exception.magic, 0x13572468)

        # 2. Valid IMG_COMMON followed by unknown second magic raises MagicException
        bad_second = struct.pack("ii", magic.by_name["IMG_COMMON"], 0x12345678)
        with self.assertRaises(images.MagicException) as ctx2:
            images.loads(bad_second)
        self.assertEqual(ctx2.exception.magic, 0x12345678)

        # 3. Valid IMG_SERVICE followed by unknown second magic raises MagicException
        bad_service_second = struct.pack("ii", magic.by_name["IMG_SERVICE"], 0x12345678)
        with self.assertRaises(images.MagicException) as ctx3:
            images.loads(bad_service_second)
        self.assertEqual(ctx3.exception.magic, 0x12345678)

        # 4. 0-byte empty file and 2-byte truncated header raise struct.error
        with self.assertRaises(struct.error):
            images.loads(b"")
        with self.assertRaises(struct.error):
            images.loads(b"\x01\x02")

        # 5. Truncated second magic after IMG_COMMON raises struct.error
        with self.assertRaises(struct.error):
            images.loads(struct.pack("i", magic.by_name["IMG_COMMON"]) + b"\x01")

        # 6. Truncated entry size (only 2 bytes after header) and truncated protobuf wire varint
        with self.assertRaises(struct.error):
            images.loads(
                struct.pack("ii", magic.by_name["IMG_COMMON"], magic.by_name["PSTREE"])
                + b"\x01\x02"
            )
        truncated_entry = (
            struct.pack("ii", magic.by_name["IMG_COMMON"], magic.by_name["PSTREE"])
            + struct.pack("i", 100)
            + b"\x08\x80"
        )
        with self.assertRaises(Exception):
            images.loads(truncated_entry)

        # 7. Dumping an image with an unknown magic name raises Exception
        with self.assertRaises(Exception):
            images.dumps({"magic": "NON_EXISTENT_MAGIC", "entries": []})


class CritCliTestCase(unittest.TestCase):
    """Unit tests for crit CLI interface (crit/crit/__main__.py)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(dir=".")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        # Reset global explorer caches between tests
        crit_main.files_img = None
        crit_main.files_cache.clear()
        for ft in crit_main.file_types.values():
            ft["img"] = None

    def run_cli(self, args, stdin_bytes=None):
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        exit_code = 0

        if stdin_bytes is not None:
            fake_stdin = mock.MagicMock()
            fake_stdin.isatty.return_value = False
            fake_stdin.buffer = io.BytesIO(stdin_bytes)
        else:
            fake_stdin = sys.stdin

        with mock.patch.object(sys, "argv", ["crit"] + list(args)), \
                mock.patch.object(sys, "stdin", fake_stdin), \
                redirect_stdout(stdout_buf), \
                redirect_stderr(stderr_buf):
            try:
                crit_main.main()
            except SystemExit as exc:
                exit_code = exc.code if isinstance(exc.code, int) else 1

        return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_cli_no_args_and_error_exit_codes(self):
        # 1. No subcommand / arguments -> exit code 1 or 2
        code, _, err = self.run_cli([])
        self.assertNotEqual(code, 0)

        # 2. Non-existent input file raises FileNotFoundError
        missing_path = os.path.join(self.tmpdir, "does-not-exist.img")
        with self.assertRaises(FileNotFoundError):
            self.run_cli(["decode", "-i", missing_path])
        with self.assertRaises(FileNotFoundError):
            self.run_cli(["info", missing_path])
        with self.assertRaises(FileNotFoundError):
            self.run_cli(["show", missing_path])

        # 3. 0-byte empty file raises struct.error on decode/info/show
        empty_path = os.path.join(self.tmpdir, "empty.img")
        with open(empty_path, "wb"):
            pass
        with self.assertRaises(struct.error):
            self.run_cli(["decode", "-i", empty_path])
        with self.assertRaises(struct.error):
            self.run_cli(["info", empty_path])

        # 4. Corrupted / unknown magic file exits with code 1 and prints "Unknown magic"
        bad_magic_path = os.path.join(self.tmpdir, "corrupt.img")
        with open(bad_magic_path, "wb") as f:
            f.write(struct.pack("ii", 0x24681357, 0))

        code, _, err = self.run_cli(["decode", "-i", bad_magic_path])
        self.assertEqual(code, 1)
        self.assertIn("Unknown magic", err)

        code, _, err = self.run_cli(["show", bad_magic_path])
        self.assertEqual(code, 1)
        self.assertIn("Unknown magic", err)

        # 5. Passing binary non-UTF8 protobuf image to `crit encode` exits with code 1
        binary_path = os.path.join(self.tmpdir, "binary.img")
        with open(binary_path, "wb") as f:
            f.write(b"\x80\x81\x82invalid-utf8")
        code, _, err = self.run_cli(["encode", "-i", binary_path])
        self.assertEqual(code, 1)
        self.assertIn("Cannot read JSON", err)

    def test_cli_decode_encode_show_and_info(self):
        payload = b"socket-queue-bytes"
        skq_img = {
            "magic": "SK_QUEUES",
            "entries": [
                {
                    "id_for": 42,
                    "length": len(payload),
                    "extra": base64.encodebytes(payload).decode("utf-8"),
                }
            ],
        }
        img_path = os.path.join(self.tmpdir, "sk-queues.img")
        json_path = os.path.join(self.tmpdir, "sk-queues.json")
        reencoded_path = os.path.join(self.tmpdir, "sk-queues.re.img")

        with open(img_path, "wb") as f:
            pycriu.images.dump(copy.deepcopy(skq_img), f)

        # `crit decode` to file and stdout (compact JSON)
        code, out, _ = self.run_cli(["decode", "-i", img_path])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), skq_img)
        self.assertEqual(len(out.strip().splitlines()), 1)

        code, _, _ = self.run_cli(["decode", "--pretty", "-i", img_path, "-o", json_path])
        self.assertEqual(code, 0)
        with open(json_path, "r") as f:
            pretty_text = f.read()
        self.assertGreater(len(pretty_text.splitlines()), 1)
        self.assertEqual(json.loads(pretty_text), skq_img)

        # `crit encode` back to binary image and verify byte-for-byte equality
        code, _, _ = self.run_cli(["encode", "-i", json_path, "-o", reencoded_path])
        self.assertEqual(code, 0)
        with open(img_path, "rb") as f1, open(reencoded_path, "rb") as f2:
            self.assertEqual(f1.read(), f2.read())

        # `crit show` (pretty JSON on stdout) and `crit show --nopl` (omits payload)
        code, show_out, _ = self.run_cli(["show", img_path])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(show_out), skq_img)

        code, show_nopl_out, _ = self.run_cli(["show", "--nopl", img_path])
        self.assertEqual(code, 0)
        parsed_nopl = json.loads(show_nopl_out)
        self.assertEqual(parsed_nopl["entries"][0]["extra"], "... <%dB>" % len(payload))

        # `crit info` on standard entry image
        ps_path = os.path.join(self.tmpdir, "pstree.img")
        with open(ps_path, "wb") as f:
            pycriu.images.dump(
                {
                    "magic": "PSTREE",
                    "entries": [
                        {"pid": 1, "ppid": 0, "pgid": 1, "sid": 1, "threads": [1]},
                        {"pid": 2, "ppid": 1, "pgid": 1, "sid": 1, "threads": [2]},
                    ],
                },
                f,
            )
        code, info_out, _ = self.run_cli(["info", ps_path])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(info_out), {"magic": "PSTREE", "count": 2})

    def test_cli_explore_ps_fds_mems_rss(self):
        # Create a synthetic checkpoint directory to test `crit x <dir> ps|fds|mems|rss`
        def dump_img(name, obj):
            with open(os.path.join(self.tmpdir, name), "wb") as f:
                pycriu.images.dump(obj, f)

        dump_img(
            "pstree.img",
            {
                "magic": "PSTREE",
                "entries": [
                    {"pid": 1, "ppid": 0, "pgid": 1, "sid": 1, "threads": [1]},
                    {"pid": 2, "ppid": 1, "pgid": 1, "sid": 1, "threads": [2]},
                ],
            },
        )
        for pid, comm in ((1, "init-proc"), (2, "child-proc")):
            dump_img(
                "core-%d.img" % pid,
                {
                    "magic": "CORE",
                    "entries": [
                        {
                            "mtype": "X86_64",
                            "tc": {
                                "task_state": 1,
                                "exit_code": 0,
                                "personality": 0,
                                "flags": 0,
                                "blk_sigset": 0,
                                "comm": comm,
                            },
                        }
                    ],
                },
            )
            dump_img(
                "ids-%d.img" % pid,
                {
                    "magic": "IDS",
                    "entries": [
                        {"vm_id": pid, "files_id": pid, "fs_id": pid, "sighand_id": pid}
                    ],
                },
            )
            dump_img(
                "fdinfo-%d.img" % pid,
                {
                    "magic": "FDINFO",
                    "entries": [{"id": 10, "flags": 0, "type": "REG", "fd": 0}],
                },
            )
            dump_img(
                "fs-%d.img" % pid,
                {"magic": "FS", "entries": [{"cwd_id": 10, "root_id": 10}]},
            )
            dump_img(
                "mm-%d.img" % pid,
                {
                    "magic": "MM",
                    "entries": [
                        {
                            "mm_start_code": 0x400000,
                            "mm_end_code": 0x401000,
                            "mm_start_data": 0x401000,
                            "mm_end_data": 0x402000,
                            "mm_start_stack": 0x7FFF0000,
                            "mm_start_brk": 0x500000,
                            "mm_brk": 0x501000,
                            "mm_arg_start": 0x7FFF0100,
                            "mm_arg_end": 0x7FFF0200,
                            "mm_env_start": 0x7FFF0200,
                            "mm_env_end": 0x7FFF0300,
                            "exe_file_id": 10,
                            "vmas": [
                                {
                                    "start": 0x400000,
                                    "end": 0x402000,
                                    "pgoff": 0,
                                    "shmid": 10,
                                    "prot": 5,
                                    "flags": 2,
                                    "status": (1 << 0) | (1 << 6),
                                    "fd": -1,
                                }
                            ],
                        }
                    ],
                },
            )
            dump_img(
                "pagemap-%d.img" % pid,
                {
                    "magic": "PAGEMAP",
                    "entries": [
                        {"pages_id": pid},
                        {"vaddr": 0x400000, "compat_nr_pages": 1, "nr_pages": 1, "flags": 4},
                    ],
                },
            )

        dump_img(
            "reg-files.img",
            {
                "magic": "REG_FILES",
                "entries": [
                    {
                        "id": 10,
                        "flags": 0,
                        "pos": 0,
                        "fown": {"uid": 0, "euid": 0, "signum": 0, "pid_type": 0, "pid": 0},
                        "name": "/usr/bin/app",
                    }
                ],
            },
        )

        code, ps_out, _ = self.run_cli(["x", self.tmpdir, "ps"])
        self.assertEqual(code, 0)
        self.assertIn("init-proc", ps_out)
        self.assertIn("child-proc", ps_out)

        code, fds_out, _ = self.run_cli(["x", self.tmpdir, "fds"])
        self.assertEqual(code, 0)
        self.assertIn("/usr/bin/app", fds_out)

        code, mems_out, _ = self.run_cli(["x", self.tmpdir, "mems"])
        self.assertEqual(code, 0)
        self.assertIn("00400000-00402000", mems_out)
        self.assertIn("r-x", mems_out)

        code, rss_out, _ = self.run_cli(["x", self.tmpdir, "rss"])
        self.assertEqual(code, 0)
        self.assertIn("400000", rss_out)


if __name__ == "__main__":
    unittest.main()
