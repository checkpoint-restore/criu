#!/usr/bin/env python2
import os, pty, sys, subprocess
import termios, fcntl, time, signal

cr_bin = "../../../criu/criu"

os.chdir(os.getcwd())

def create_pty():
        (fd1, fd2) = pty.openpty()
        return (os.fdopen(fd1, "w+"), os.fdopen(fd2, "w+"))

if not os.access("work", os.X_OK):
    os.mkdir("work", 0755)

open("running", "w").close()
m,s = create_pty()
p = os.pipe()
pr = os.fdopen(p[0], "r")
pw = os.fdopen(p[1], "w")

pid = os.fork()
if pid == 0:
    m.close()
    os.setsid()
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    fcntl.ioctl(s.fileno(), termios.TIOCSCTTY, 1)
    pr.close()
    pw.close()
    while True:
        if not os.access("running", os.F_OK):
            sys.exit(0)
        time.sleep(1)
    sys.exit(1)

pw.close()
pr.read(1)

cmd = [cr_bin, "dump", "-j", "-t", str(pid), "-D", "work", "-v"]
print("Run: %s" % " ".join(cmd))
ret = subprocess.Popen(cmd).wait()
if ret != 0:
    sys.exit(1)
os.wait()

os.unlink("running")
m,s = create_pty()
cpid = os.fork()
if cpid == 0:
    os.setsid()
    fcntl.ioctl(m.fileno(), termios.TIOCSCTTY, 1)
    cmd = [cr_bin, "restore", "-j", "-D", "work", "-v"]
    print("Run: %s" % " ".join(cmd))
    ret = subprocess.Popen([cr_bin, "restore", "-j", "-D", "work", "-v"]).wait()
    if ret != 0:
        sys.exit(1)
    sys.exit(0)

pid, status = os.wait()
if status != 0:
    print("A child process exited with %d" % status)
    sys.exit(1)

