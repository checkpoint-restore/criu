#!/usr/bin/python3
"""
`pip uninstall` doesn't support `--prefix`.
https://github.com/pypa/pip/issues/11213
"""
import argparse
import os
import shutil
import site
import subprocess
import sys

import importlib_metadata


def add_site_dir(prefix: str):
    """
    Add site directory with prefix to sys.path and update PYTHONPATH.
    """
    # If prefix is used, we need to make sure that we
    # do not uninstall other packages from the system paths.
    sys.path = []
    site.PREFIXES = [prefix]
    pkgs = site.getsitepackages()
    for path in pkgs:
        site.addsitedir(path)
        if 'dist-packages' in path:
            # Ubuntu / Debian might use both dist- and site- packages.
            site.addsitedir(path.replace('dist-packages', 'site-packages'))
    os.environ['PYTHONPATH'] = os.pathsep.join(sys.path)


def uninstall_module(package_name: str, prefix=None):
    """
    Enable support for '--prefix' with 'pip uninstall'.
    """
    dist_info_path = None
    if prefix:
        add_site_dir(prefix)
        try:
            distribution = next(importlib_metadata.Distribution.discover(name=package_name))
            dist_info_path = str(distribution._path)
        except StopIteration:
            print(f"Skipping {package_name} as it is not installed.")
            sys.exit(0)

    command = [sys.executable, '-m', 'pip', 'uninstall', '-y', package_name]
    try:
        subprocess.check_call(command, env=os.environ)
        if dist_info_path and os.path.isdir(dist_info_path):
            # .dist-info files are not cleaned up when the package
            # has been installed with --prefix.
            # https://github.com/pypa/pip/issues/5573
            shutil.rmtree(dist_info_path)
            if 'dist-packages' in dist_info_path:
                shutil.rmtree(dist_info_path.replace('dist-packages', 'site-packages'))
    except subprocess.CalledProcessError as err:
        print(f'Error uninstalling package {package_name}: {err}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('module_name', help='The name of the module to uninstall')
    parser.add_argument('--prefix', help='The prefix where the module was installed')
    args = parser.parse_args()
    uninstall_module(args.module_name, args.prefix)
