#!/usr/bin/env python
import subprocess
import os, sys, time, signal, pty

master, slave = pty.openpty()

p = subprocess.Popen(["setsid", "--ctty", "sleep", "10000"],
                     stdin=slave,
                     stdout=slave,
                     stderr=slave,
                     close_fds=True)
st = os.stat("/proc/self/fd/%d" % slave)
ttyid = "tty[%x:%x]" % (st.st_rdev, st.st_dev)
os.close(slave)
time.sleep(1)

ret = subprocess.Popen([
    "../../../criu/criu", "dump", "-t",
    str(p.pid), "-v4", "--external", ttyid
]).wait()
if ret:
    sys.exit(ret)
p.wait()

new_master, slave = pty.openpty()  # get another pty pair
os.close(master)

ttyid = "fd[%d]:tty[%x:%x]" % (slave, st.st_rdev, st.st_dev)

ret = subprocess.Popen([
    "../../../criu/criu", "restore", "-v4", "--inherit-fd", ttyid,
    "--restore-sibling", "--restore-detach"
]).wait()
if ret:
    sys.exit(ret)
os.close(slave)
os.waitpid(-1, os.WNOHANG)  # is the process alive

os.close(new_master)
_, status = os.wait()
if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGHUP:
    print(status)
    sys.exit(1)

print("PASS")
