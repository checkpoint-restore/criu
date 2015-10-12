import os

class pipef:
	def __init__(self, fd):
		self.__fd = fd

	def read(self, blen):
		return os.read(self.__fd, blen)

	def write(self, msg):
		return os.write(self.__fd, msg)

	def flush(self):
		pass

	def close(self):
		os.close(self.__fd)
		self.__fd = -1

	def fileno(self):
		return self.__fd

def create_fds():
	(fd1, fd2) = os.pipe()
	return (pipef(fd2), pipef(fd1))

def filename(pipef):
	return 'pipe:[%d]' % os.fstat(pipef.fileno()).st_ino

def dump_opts(sockf):
	return [ ]
