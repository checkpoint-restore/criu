#!/usr/bin/env python3

import argparse
import os
import sys

import pycriu.images


COMPRESS_OFF = 0
COMPRESS_BLOCK = 1
PE_PRESENT = 4
EXPECTED_BLOCK_SIZES = {"block-4k": 4 * 1024, "block-64k": 64 * 1024}


def inventory_compression(directory, mode, version):
    expected_mode = COMPRESS_OFF if mode == "plain" else COMPRESS_BLOCK
    expected_version = int(version)

    with open(os.path.join(directory, "inventory.img"), "rb") as image:
        inventory = pycriu.images.load(image)["entries"][0]

    if inventory["img_version"] != expected_version:
        print(
            "FAIL: %s inventory version is %s, expected %s"
            % (directory, inventory["img_version"], expected_version)
        )
        return 1
    if int(inventory.get("compress", 0)) != expected_mode:
        print(
            "FAIL: %s inventory compression mode is %s, expected %s"
            % (directory, inventory.get("compress"), expected_mode)
        )
        return 1

    block_size = inventory.get("compress_block_size")
    if expected_mode == COMPRESS_BLOCK:
        expected_block_size = EXPECTED_BLOCK_SIZES[mode]
        if int(block_size or 0) != expected_block_size:
            print(
                "FAIL: %s inventory block size is %s, expected %s"
                % (directory, block_size, expected_block_size)
            )
            return 1
    elif block_size is not None:
        print(
            "FAIL: %s has unexpected compression block size %s"
            % (directory, block_size)
        )
        return 1

    return 0


def legacy_inventory(directory):
    path = os.path.join(directory, "inventory.img")
    with open(path, "rb") as image:
        img = pycriu.images.load(image)

    inventory = img["entries"][0]
    if int(inventory.get("compress", 0)) != COMPRESS_OFF:
        print("FAIL: %s is compressed, cannot make it a legacy image" % path)
        return 1

    inventory["img_version"] = 0
    inventory.pop("compress", None)
    inventory.pop("compress_block_size", None)

    with open(path, "wb") as image:
        pycriu.images.dump(img, image)

    return 0


def present_payload(directory, pid):
    path = os.path.join(directory, "pagemap-%s.img" % pid)
    with open(path, "rb") as image:
        entries = pycriu.images.load(image)["entries"][1:]

    if not any(int(entry.get("flags", 0)) & PE_PRESENT for entry in entries):
        print("FAIL: %s contains no present page payload" % path)
        return 1

    return 0


def toggle_page(directory, pid, address_file):
    path = os.path.join(directory, "pagemap-%s.img" % pid)
    if os.path.exists(address_file):
        with open(address_file) as saved:
            address = int(saved.read().strip(), 16)
    else:
        with open(path, "rb") as image:
            entries = pycriu.images.load(image)["entries"][1:]
        present = [
            entry
            for entry in entries
            if int(entry.get("flags", 0)) & PE_PRESENT
        ]
        if not present:
            print("FAIL: no present mapping available to modify in %s" % path)
            return 1
        entry = max(present, key=lambda item: int(item.get("nr_pages", 0)))
        address = int(entry["vaddr"])
        with open(address_file, "w") as saved:
            saved.write("%x\n" % address)

    with open("/proc/%s/mem" % pid, "r+b", buffering=0) as memory:
        value = os.pread(memory.fileno(), 1, address)
        if len(value) != 1:
            raise RuntimeError("short read from workload memory")
        if os.pwrite(memory.fileno(), bytes([value[0] ^ 0xFF]), address) != 1:
            raise RuntimeError("short write to workload memory")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Inspect incremental compression images and toggle test memory"
    )
    subparsers = parser.add_subparsers(dest="command")

    inventory = subparsers.add_parser("inventory-compression")
    inventory.add_argument("directory")
    inventory.add_argument(
        "mode", choices=("plain", *EXPECTED_BLOCK_SIZES.keys())
    )
    inventory.add_argument("version", type=int)

    legacy = subparsers.add_parser("legacy-inventory")
    legacy.add_argument("directory")

    payload = subparsers.add_parser("present-payload")
    payload.add_argument("directory")
    payload.add_argument("pid")

    toggle = subparsers.add_parser("toggle-page")
    toggle.add_argument("directory")
    toggle.add_argument("pid")
    toggle.add_argument("address_file")

    args = parser.parse_args()
    if args.command is None:
        parser.error("a command is required")
    if args.command == "inventory-compression":
        return inventory_compression(args.directory, args.mode, args.version)
    if args.command == "legacy-inventory":
        return legacy_inventory(args.directory)
    if args.command == "present-payload":
        return present_payload(args.directory, args.pid)
    return toggle_page(args.directory, args.pid, args.address_file)


if __name__ == "__main__":
    sys.exit(main())
