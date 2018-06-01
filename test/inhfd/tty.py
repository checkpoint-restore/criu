import os, pty
import termios, fcntl

def child_prep(fd):
	fcntl.ioctl(fd.fileno(), termios.TIOCSCTTY, 1)

def create_fds():
	(fd1, fd2) = pty.openpty()
	return (os.fdopen(fd2, "wb"), os.fdopen(fd1, "rb"))

def filename(pipef):
	st = os.fstat(pipef.fileno())
	return 'tty[%x:%x]' % (st.st_rdev, st.st_dev)

def dump_opts(sockf):
	st = os.fstat(sockf.fileno())
	return ["--external", 'tty[%x:%x]' % (st.st_rdev, st.st_dev)]
