#!/usr/bin/env python3
"""
Check the cgroups dumped for a controller in a cgroup image.

Usage: check-dirs.py CONTROLLER IMAGE.json

The cgroups of the dumped sets are "/" and "/child", so the controller is
expected to have a single cgroup root (dumped with an empty name) with the
nested cgroup as its only child. Two cgroup roots mean the ancestor cgroup
was collected after its descendant, which loses the nesting.
"""

import json
import sys


def dir_names(dirs):
    return [d["dir_name"] for d in dirs]


def main():
    controller, image = sys.argv[1], sys.argv[2]

    with open(image) as f:
        entry = json.load(f)["entries"][0]

    found = [c for c in entry["controllers"] if controller in c["cnames"]]
    if len(found) != 1:
        sys.exit("found %d entries for controller %s, expected 1" % (len(found), controller))

    dirs = found[0].get("dirs", [])
    if dir_names(dirs) != [""]:
        sys.exit("cgroup roots of %s are %s, expected a single unnamed one" % (controller, dir_names(dirs)))

    children = dirs[0].get("children", [])
    if dir_names(children) != ["child"]:
        sys.exit("children of the cgroup root are %s, expected ['child']" % dir_names(children))


if __name__ == "__main__":
    main()
