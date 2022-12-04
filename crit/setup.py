import os
from setuptools import setup, find_packages


def get_version():
    version = '0.0.1'
    env = os.environ
    if 'CRIU_VERSION_MAJOR' in env and 'CRIU_VERSION_MINOR' in env:
        version = '{}.{}'.format(
            env['CRIU_VERSION_MAJOR'],
            env['CRIU_VERSION_MINOR']
        )
        if 'CRIU_VERSION_SUBLEVEL' in env and env['CRIU_VERSION_SUBLEVEL']:
            version += '.' + env['CRIU_VERSION_SUBLEVEL']
    return version


setup(
    name='crit',
    version=get_version(),
    description='CRiu Image Tool',
    author='CRIU team',
    author_email='criu@openvz.org',
    license='GPLv2',
    url='https://github.com/checkpoint-restore/criu',
    packages=find_packages('.'),
    scripts=['crit'],
    install_requires=[],
)
