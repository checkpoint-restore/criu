from setuptools import setup, find_packages
import pycriu

setup(
    name='crit',
    version=pycriu.__version__,
    description='CRiu Image Tool',
    author='CRIU team',
    author_email='criu@openvz.org',
    license='GPLv2',
    url='https://github.com/checkpoint-restore/criu',
    packages=find_packages('.'),
    scripts=['crit'],
    install_requires=[],
)
