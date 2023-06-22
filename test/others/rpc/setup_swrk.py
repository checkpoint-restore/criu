import sys
import socket
import subprocess

def setup_swrk():
    print('Connecting to CRIU in swrk mode.')
    s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    swrk = subprocess.Popen(['./criu', "swrk", "%d" % s1.fileno()], pass_fds=[s1.fileno()])
    s1.close()
    return swrk, s2
