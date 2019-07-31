import sys
import socket
import subprocess

def setup_swrk():
    print('Connecting to CRIU in swrk mode.')
    s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    kwargs = {}
    if sys.version_info.major == 3:
        kwargs["pass_fds"] = [s1.fileno()]

    swrk = subprocess.Popen(['./criu', "swrk", "%d" % s1.fileno()], **kwargs)
    s1.close()
    return swrk, s2

