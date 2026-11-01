#!/usr/bin/env python3
"""Helpers for legacy images to test backward compatibility.

make_legacy_pagemap_images() rewrites pagemap images in the format
written by CRIU < 4.2. These CRIU versions store the page count of
pagemap entries in compat_nr_pages only, without nr_pages.
"""

import argparse
import glob
import os
import sys

import pycriu.images


def make_legacy_pagemap_images(directory):
    paths = sorted(glob.glob(os.path.join(directory, "pagemap-*.img")))
    if not paths:
        print("FAIL: no pagemap images in %s" % directory)
        return 1

    for path in paths:
        with open(path, "rb") as image_file:
            pagemap = pycriu.images.load(image_file)

        for entry in pagemap["entries"][1:]:
            entry["compat_nr_pages"] = entry.pop("nr_pages")

        with open(path, "wb") as image_file:
            pycriu.images.dump(pagemap, image_file)

    return 0


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    pagemap_parser = subparsers.add_parser("make-legacy-pagemap")
    pagemap_parser.add_argument("directory")

    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "make-legacy-pagemap":
        return make_legacy_pagemap_images(args.directory)
    raise AssertionError("unhandled command %s" % args.command)


if __name__ == "__main__":
    sys.exit(main())
