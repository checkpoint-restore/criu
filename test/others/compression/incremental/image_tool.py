#!/usr/bin/env python3

import argparse
import os
import sys

import pycriu.images


PE_PRESENT = 4
EXPECTED_REGION_SIZE = 64 * 1024


def inventory_compression(directory, mode, version):
    expected_mode = {"plain": 0, "page": 1, "region": 2}[mode]
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

    region_size = inventory.get("compress_region_size")
    if expected_mode == 2:
        if int(region_size or 0) != EXPECTED_REGION_SIZE:
            print(
                "FAIL: %s inventory region size is %s, expected 65536"
                % (directory, region_size)
            )
            return 1
    elif region_size is not None:
        print(
            "FAIL: %s has unexpected compression region size %s"
            % (directory, region_size)
        )
        return 1

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
    inventory.add_argument("mode", choices=("plain", "page", "region"))
    inventory.add_argument("version", type=int)

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
    if args.command == "present-payload":
        return present_payload(args.directory, args.pid)
    return toggle_page(args.directory, args.pid, args.address_file)


if __name__ == "__main__":
    sys.exit(main())
