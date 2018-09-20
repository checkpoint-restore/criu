import os


def create_fds():
	pipes = []
	for i in range(10):
		(fd1, fd2) = os.pipe()
		pipes.append((os.fdopen(fd2, "wb"), os.fdopen(fd1, "rb")))
	return pipes


def filename(pipef):
	return 'pipe:[%d]' % os.fstat(pipef.fileno()).st_ino


def dump_opts(sockf):
	return []
