from distutils.core import setup

setup(name="crit",
      version="0.0.1",
      description="CRiu Image Tool",
      author="CRIU team",
      author_email="criu@openvz.org",
      url="https://github.com/checkpoint-restore/criu",
      package_dir={'pycriu': 'lib/py'},
      packages=["pycriu", "pycriu.images"],
      scripts=["crit/crit"])
