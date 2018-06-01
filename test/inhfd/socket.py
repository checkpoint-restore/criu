import socket
import os

def create_fds():
	(sk1, sk2) = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
	return (sk1.makefile("wb"), sk2.makefile("rb"))

def __sock_ino(sockf):
	return os.fstat(sockf.fileno()).st_ino

def filename(sockf):
	return 'socket:[%d]' % __sock_ino(sockf)

def dump_opts(sockf):
	return ['--external', 'unix[%d]' % __sock_ino(sockf)]
