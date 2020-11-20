import fcntl
import os
import pty
import termios

ctl = False


def child_prep(fd):
    global ctl
    if ctl:
        return
    ctl = True
    fcntl.ioctl(fd.fileno(), termios.TIOCSCTTY, 1)


def create_fds():
    ttys = []
    for i in range(10):
        (fd1, fd2) = pty.openpty()
        newattr = termios.tcgetattr(fd1)
        newattr[3] &= ~termios.ICANON & ~termios.ECHO
        termios.tcsetattr(fd1, termios.TCSADRAIN, newattr)
        ttys.append((os.fdopen(fd1, "wb"), os.fdopen(fd2, "rb")))
    return ttys


def filename(pipef):
    st = os.fstat(pipef.fileno())
    return 'tty[%x:%x]' % (st.st_rdev, st.st_dev)


def dump_opts(sockf):
    st = os.fstat(sockf.fileno())
    return "--external", 'tty[%x:%x]' % (st.st_rdev, st.st_dev)
