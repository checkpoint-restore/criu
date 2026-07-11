#!/usr/bin/env python3

import glob
import os
import random
import tempfile

import lz4.block
import pycriu
from crit import __main__ as crit_main


PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PE_PRESENT = 1 << 2
MAP_SHARED = 1 << 0
MAP_PRIVATE = 1 << 1
MAP_ANON = 0x20
MAP_HUGETLB = 0x40000
VMA_AREA_REGULAR = 1 << 0
VMA_ANON_SHARED = 1 << 8
VMA_ANON_PRIVATE = 1 << 9
VMA_EXT_PLUGIN = 1 << 27


def write_image(directory, name, image):
    with open(os.path.join(directory, name), "wb") as image_file:
        pycriu.images.dump(image, image_file)


def inventory(directory, compress=None, image_version=2):
    entry = {"img_version": image_version}
    if compress is not None:
        entry["compress"] = compress
    write_image(
        directory,
        "inventory.img",
        {"magic": "INVENTORY", "entries": [entry]},
    )


def pagemap(directory, image_id, pages_id, entries, shared=False):
    prefix = "pagemap-shmem-" if shared else "pagemap-"
    write_image(
        directory,
        "%s%d.img" % (prefix, image_id),
        {
            "magic": "PAGEMAP",
            "entries": [{"pages_id": pages_id}] + entries,
        },
    )


def vma(start, page_count, flags, status, shmid=0, pgoff=0):
    return {
        "start": start,
        "end": start + page_count * PAGE_SIZE,
        "pgoff": pgoff,
        "shmid": shmid,
        "prot": 3,
        "flags": flags,
        "status": status,
        "fd": -1,
    }


def mm(directory, task_id, vmas):
    entry = {
        "mm_start_code": 0,
        "mm_end_code": 0,
        "mm_start_data": 0,
        "mm_end_data": 0,
        "mm_start_stack": 0,
        "mm_start_brk": 0,
        "mm_brk": 0,
        "mm_arg_start": 0,
        "mm_arg_end": 0,
        "mm_env_start": 0,
        "mm_env_end": 0,
        "exe_file_id": 0,
        "vmas": vmas,
    }
    write_image(
        directory,
        "mm-%d.img" % task_id,
        {"magic": "MM", "entries": [entry]},
    )


def load(directory, name):
    with open(os.path.join(directory, name), "rb") as image_file:
        return pycriu.images.load(image_file)


def image_bytes(directory):
    contents = {}
    for path in glob.glob(os.path.join(directory, "*.img")):
        with open(path, "rb") as image_file:
            contents[path] = image_file.read()
    return contents


def ordinary_checkpoint(directory, page, task_id=1):
    inventory(directory)
    with open(os.path.join(directory, "pages-1.img"), "wb") as pages:
        pages.write(page)
    base = 0x100000
    pagemap(
        directory,
        task_id,
        1,
        [
            {
                "vaddr": base,
                "compat_nr_pages": 1,
                "nr_pages": 1,
                "flags": PE_PRESENT,
            }
        ],
    )
    mm(
        directory,
        task_id,
        [
            vma(
                base,
                1,
                MAP_PRIVATE | MAP_ANON,
                VMA_AREA_REGULAR | VMA_ANON_PRIVATE,
            )
        ],
    )


def test_sign_extended_ranges():
    # Native 32-bit x86 pagemaps sign-extend pointers while mm VMA bounds do
    # not.
    sign_extended_ranges = [(0x90000000, 0x90000000 + PAGE_SIZE)]
    assert crit_main._address_in_ranges(
        0xFFFFFFFF90000000,
        sign_extended_ranges,
        crit_main._range_starts(sign_extended_ranges),
    )


def test_exceptional_mappings_and_timestamps():
    # Private hugetlb and external-plugin ranges use task virtual addresses;
    # shared hugetlb ranges use shmid and pgoff in pagemap-shmem images. Verify
    # both translations and ensure only the ordinary pages become LZ4 blocks.
    with tempfile.TemporaryDirectory(dir=".") as directory:
        inventory(directory)
        task_base = 0x100000
        task_pages = b"A" * PAGE_SIZE + b"B" * PAGE_SIZE + b"C" * PAGE_SIZE
        shared_pages = b"D" * PAGE_SIZE + b"E" * PAGE_SIZE
        with open(os.path.join(directory, "pages-1.img"), "wb") as pages:
            pages.write(task_pages)
        with open(os.path.join(directory, "pages-2.img"), "wb") as pages:
            pages.write(shared_pages)
        pagemap(
            directory,
            100,
            1,
            [
                {
                    "vaddr": task_base,
                    "compat_nr_pages": 3,
                    "nr_pages": 3,
                    "flags": PE_PRESENT,
                }
            ],
        )
        pagemap(
            directory,
            77,
            2,
            [
                {
                    "vaddr": 0,
                    "compat_nr_pages": 2,
                    "nr_pages": 2,
                    "flags": PE_PRESENT,
                }
            ],
            shared=True,
        )
        mm(
            directory,
            100,
            [
                vma(
                    task_base,
                    1,
                    MAP_PRIVATE | MAP_ANON | MAP_HUGETLB,
                    VMA_AREA_REGULAR | VMA_ANON_PRIVATE,
                ),
                vma(
                    task_base + PAGE_SIZE,
                    1,
                    MAP_PRIVATE | MAP_ANON,
                    VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_EXT_PLUGIN,
                ),
                vma(
                    task_base + 2 * PAGE_SIZE,
                    1,
                    MAP_PRIVATE | MAP_ANON,
                    VMA_AREA_REGULAR | VMA_ANON_PRIVATE,
                ),
                vma(
                    0x200000,
                    1,
                    MAP_SHARED | MAP_ANON | MAP_HUGETLB,
                    VMA_AREA_REGULAR | VMA_ANON_SHARED,
                    shmid=77,
                ),
                vma(
                    0x300000,
                    1,
                    MAP_SHARED | MAP_ANON,
                    VMA_AREA_REGULAR | VMA_ANON_SHARED,
                    shmid=77,
                    pgoff=PAGE_SIZE,
                ),
            ],
        )

        # Make source atime older than mtime so an ordinary read would change
        # it.
        original_times = {}
        for index, path in enumerate(
            sorted(glob.glob(os.path.join(directory, "*.img")))
        ):
            times = (946684800123456789 + index, 978307200987654321 + index)
            os.utime(path, ns=times)
            before = os.stat(path)
            original_times[path] = (before.st_atime_ns, before.st_mtime_ns)

        assert (
            crit_main.compress_cmd(
                {"dir": directory, "in_place": True, "acceleration": 1}
            )
            == 0
        )
        for path, times in original_times.items():
            after = os.stat(path)
            assert (after.st_atime_ns, after.st_mtime_ns) == times, path

        task_pm = load(directory, "pagemap-100.img")["entries"][1]
        shared_pm = load(directory, "pagemap-shmem-77.img")["entries"][1]
        assert task_pm["compressed_size"][:2] == [PAGE_SIZE, PAGE_SIZE]
        assert 0 < task_pm["compressed_size"][2] < PAGE_SIZE
        assert shared_pm["compressed_size"][0] == PAGE_SIZE
        assert 0 < shared_pm["compressed_size"][1] < PAGE_SIZE

        decompressed_times = {}
        for index, path in enumerate(
            sorted(glob.glob(os.path.join(directory, "*.img")))
        ):
            times = (1009843200123456789 + index, 1041379200987654321 + index)
            os.utime(path, ns=times)
            before = os.stat(path)
            decompressed_times[path] = (before.st_atime_ns, before.st_mtime_ns)

        assert (
            crit_main.decompress_cmd({"dir": directory, "in_place": True}) == 0
        )
        for path, times in decompressed_times.items():
            after = os.stat(path)
            assert (after.st_atime_ns, after.st_mtime_ns) == times, path
        with open(os.path.join(directory, "pages-1.img"), "rb") as pages:
            assert pages.read() == task_pages
        with open(os.path.join(directory, "pages-2.img"), "rb") as pages:
            assert pages.read() == shared_pages


def test_acceleration():
    # This page is encoded differently by fast-mode acceleration 1 and 100.
    # Comparing CRIT output to python-lz4 catches accidentally passing an
    # ignored acceleration argument to the library's default compression mode.
    rng = random.Random(1238)
    tokens = [bytes(rng.randrange(256) for _ in range(4)) for _ in range(128)]
    page = b"".join(
        tokens[(index * 17 + index // 7) % len(tokens)]
        for index in range(PAGE_SIZE // 4)
    )
    expected = {
        acceleration: lz4.block.compress(
            page,
            mode="fast",
            store_size=False,
            acceleration=acceleration,
        )
        for acceleration in (1, 100)
    }
    assert expected[1] != expected[100]

    for acceleration in (1, 100):
        with tempfile.TemporaryDirectory(dir=".") as directory:
            ordinary_checkpoint(directory, page)
            assert (
                crit_main.compress_cmd(
                    {
                        "dir": directory,
                        "in_place": True,
                        "acceleration": acceleration,
                    }
                )
                == 0
            )
            pagemap_entry = load(directory, "pagemap-1.img")["entries"][1]
            encoded = expected[acceleration]
            if len(encoded) >= crit_main.PAGE_COMPRESSION_THRESHOLD:
                assert "compressed_size" not in pagemap_entry
                with open(os.path.join(directory, "pages-1.img"), "rb") as pages:
                    assert pages.read() == page
            else:
                assert pagemap_entry["compressed_size"] == [len(encoded)]
                with open(os.path.join(directory, "pages-1.img"), "rb") as pages:
                    assert pages.read() == encoded


def test_unknown_compression_mode():
    # Unknown enum values must be rejected before the "already compressed"
    # no-op and before any temporary or replacement image is created.
    for command in ("compress", "decompress"):
        with tempfile.TemporaryDirectory(dir=".") as directory:
            ordinary_checkpoint(directory, b"F" * PAGE_SIZE)
            inventory_image = load(directory, "inventory.img")
            inventory_image["entries"][0]["compress"] = 0xFFFFFFFF
            write_image(directory, "inventory.img", inventory_image)
            before = image_bytes(directory)
            assert run_transform(command, directory) == 1
            assert image_bytes(directory) == before
            assert not glob.glob(os.path.join(directory, ".*.crit-*"))


def run_transform(command, directory):
    if command == "compress":
        return crit_main.compress_cmd(
            {"dir": directory, "in_place": True, "acceleration": 1}
        )
    return crit_main.decompress_cmd({"dir": directory, "in_place": True})


def test_unsupported_image_version():
    for image_version in (1, 4):
        for command in ("compress", "decompress"):
            with tempfile.TemporaryDirectory(dir=".") as directory:
                ordinary_checkpoint(directory, b"V" * PAGE_SIZE)
                inventory_image = load(directory, "inventory.img")
                inventory_image["entries"][0]["img_version"] = image_version
                write_image(directory, "inventory.img", inventory_image)
                before = image_bytes(directory)

                assert run_transform(command, directory) == 1
                assert image_bytes(directory) == before
                assert not glob.glob(os.path.join(directory, ".*.crit-*"))


def test_compression_requires_v1_2_inventory():
    for command in ("compress", "decompress"):
        with tempfile.TemporaryDirectory(dir=".") as directory:
            ordinary_checkpoint(directory, b"C" * PAGE_SIZE)
            inventory_image = load(directory, "inventory.img")
            inventory_image["entries"][0]["compress"] = 1
            write_image(directory, "inventory.img", inventory_image)
            before = image_bytes(directory)

            assert run_transform(command, directory) == 1
            assert image_bytes(directory) == before
            assert not glob.glob(os.path.join(directory, ".*.crit-*"))


def test_uncompressed_v1_2_inventory_is_valid():
    with tempfile.TemporaryDirectory(dir=".") as directory:
        ordinary_checkpoint(directory, b"U" * PAGE_SIZE)
        inventory_image = load(directory, "inventory.img")
        inventory_image["entries"][0]["img_version"] = 3
        write_image(directory, "inventory.img", inventory_image)
        before = image_bytes(directory)

        assert run_transform("decompress", directory) == 0
        assert image_bytes(directory) == before


def test_symlink_rejection():
    # Replacing an image symlink would sever it while transforming its target's
    # bytes with the symlink's metadata. Reject non-regular image paths instead.
    with tempfile.TemporaryDirectory(dir=".") as directory:
        ordinary_checkpoint(directory, b"G" * PAGE_SIZE)
        inventory_path = os.path.join(directory, "inventory.img")
        inventory_target = os.path.join(directory, "inventory.real")
        os.replace(inventory_path, inventory_target)
        os.symlink("inventory.real", inventory_path)
        with open(inventory_target, "rb") as inventory_file:
            before = inventory_file.read()
        assert (
            crit_main.compress_cmd(
                {"dir": directory, "in_place": True, "acceleration": 1}
            )
            == 1
        )
        assert os.path.islink(inventory_path)
        with open(inventory_target, "rb") as inventory_file:
            assert inventory_file.read() == before
        assert not glob.glob(os.path.join(directory, ".*.crit-*"))


def main():
    test_sign_extended_ranges()
    test_exceptional_mappings_and_timestamps()
    test_acceleration()
    test_unknown_compression_mode()
    test_unsupported_image_version()
    test_compression_requires_v1_2_inventory()
    test_uncompressed_v1_2_inventory_is_valid()
    test_symlink_rejection()


if __name__ == "__main__":
    main()
