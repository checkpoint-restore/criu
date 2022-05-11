import os
from distutils.core import setup

criu_version = "0.0.1"
env = os.environ

if 'CRIU_VERSION_MAJOR' in env and 'CRIU_VERSION_MINOR' in env:
    criu_version = '{}.{}'.format(
        env['CRIU_VERSION_MAJOR'],
        env['CRIU_VERSION_MINOR']
    )

    if 'CRIU_VERSION_SUBLEVEL' in env and env['CRIU_VERSION_SUBLEVEL']:
        criu_version += '.' + env['CRIU_VERSION_SUBLEVEL']

setup(name="crit",
      version=criu_version,
      description="CRiu Image Tool",
      author="CRIU team",
      author_email="criu@openvz.org",
      license="GPLv2",
      url="https://github.com/checkpoint-restore/criu",
      package_dir={'pycriu': 'lib/py'},
      packages=["pycriu", "pycriu.images"],
      scripts=["crit/crit"])
