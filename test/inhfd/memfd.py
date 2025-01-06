import ctypes
import os
libc = ctypes.CDLL(None)


def memfd_create(name, flags):
    return libc.memfd_create(name.encode('utf8'), flags)


def create_fds():
    def create_memfd_pair(name):
        fd = memfd_create(name, 0)
        fw = open('/proc/self/fd/{}'.format(fd), 'wb')
        fr = open('/proc/self/fd/{}'.format(fd), 'rb')
        os.close(fd)
        return (fw, fr)

    return [create_memfd_pair("name{}".format(i)) for i in range(10)]


def filename(f):
    name = os.readlink('/proc/self/fd/{}'.format(f.fileno()))
    name = name.replace(' (deleted)', '')
    return name


def dump_opts(sockf):
    return []
