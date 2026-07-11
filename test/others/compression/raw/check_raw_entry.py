#!/usr/bin/env python3

import argparse
import os
import sys

import pycriu.images


PE_PRESENT = 4
PE_PAYLOAD_ALIGNED = 8


def check_raw_entry(directory, pid):
    path = os.path.join(directory, "pagemap-%s.img" % pid)

    with open(path, "rb") as image:
        entries = pycriu.images.load(image)["entries"][1:]

    page_size = os.sysconf("SC_PAGE_SIZE")
    payload_offset = 0
    found = False
    found_lz4 = False
    for entry in entries:
        flags = int(entry.get("flags", 0))
        if not flags & PE_PRESENT:
            continue
        if flags & PE_PAYLOAD_ALIGNED:
            payload_offset = (payload_offset + page_size - 1) & -page_size

        is_raw_target = (
            int(entry.get("nr_pages", 0)) == 56
            and "compressed_size" not in entry
            and "total_compressed_size" not in entry
            and "region_pages" not in entry
        )
        if is_raw_target:
            if not flags & PE_PAYLOAD_ALIGNED:
                print("FAIL: all-raw entry lacks PE_PAYLOAD_ALIGNED in %s" % path)
                return 1
            if payload_offset % page_size:
                print(
                    "FAIL: all-raw entry starts at unaligned offset %d"
                    % payload_offset
                )
                return 1
            found = True

        compressed_sizes = entry.get("compressed_size")
        if compressed_sizes:
            block_pages = int(entry.get("region_pages", 0)) or 1
            remaining = int(entry.get("nr_pages", 0))
            for size in compressed_sizes:
                pages = min(block_pages, remaining)
                if 0 < int(size) < pages * page_size:
                    found_lz4 = True
                remaining -= pages
            payload_offset += sum(int(size) for size in compressed_sizes)
        else:
            payload_offset += int(entry.get("nr_pages", 0)) * page_size

    if not found:
        print(
            "FAIL: no aligned 56-page all-raw entry without compression metadata "
            "in %s" % path
        )
        return 1
    if not found_lz4:
        print("FAIL: compression test produced no LZ4-compressed block in %s" % path)
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate raw-fallback pagemap metadata"
    )
    parser.add_argument("directory")
    parser.add_argument("pid")
    args = parser.parse_args()
    return check_raw_entry(args.directory, args.pid)


if __name__ == "__main__":
    sys.exit(main())
