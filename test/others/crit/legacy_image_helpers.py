#!/usr/bin/env python3
"""Helpers for legacy images to test backward compatibility.

make_legacy_pagemap_images() rewrites pagemap images in the format written by CRIU < 4.2.
CRIU < 4.2 stores the page count of pagemap entries in compat_nr_pages
only, without nr_pages.
"""

import glob
import os
import sys

import pycriu.images


def make_legacy_pagemap_images(directory):
    paths = sorted(glob.glob(os.path.join(directory, "pagemap-*.img")))
    if not paths:
        print(f"""FAIL: no pagemap images in {directory}""")
        return 1

    for path in paths:
        with open(path, "rb") as img_file:
            pagemap = pycriu.images.load(img_file)

        for entry in pagemap["entries"][1:]:
            entry["compat_nr_pages"] = entry.pop("nr_pages")

        with open(path, "wb") as img_file:
            pycriu.images.dump(pagemap, img_file)

    return 0


if __name__ == "__main__":
    sys.exit(make_legacy_pagemap_images(sys.argv[1]))
