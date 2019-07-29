#!/usr/bin/python

import socket
import sys
import rpc_pb2 as rpc
import subprocess

print('Connecting to CRIU in swrk mode to check the version:')

s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

kwargs = {}
if sys.version_info.major == 3:
    kwargs["pass_fds"] = [s2.fileno()]

swrk = subprocess.Popen(['./criu', "swrk", "%d" % s2.fileno()], **kwargs)
s2.close()

# Create criu msg, set it's type to dump request
# and set dump options. Checkout more options in protobuf/rpc.proto
req = rpc.criu_req()
req.type = rpc.VERSION

# Send request
s1.send(req.SerializeToString())

# Recv response
resp = rpc.criu_resp()
MAX_MSG_SIZE = 1024
resp.ParseFromString(s1.recv(MAX_MSG_SIZE))

if resp.type != rpc.VERSION:
    print('RPC: Unexpected msg type')
    sys.exit(-1)
else:
    if resp.success:
        print('RPC: Success')
        print('CRIU major %d' % resp.version.major_number)
        print('CRIU minor %d' % resp.version.minor_number)
        if resp.version.HasField('gitid'):
            print('CRIU gitid %s' % resp.version.gitid)
        if resp.version.HasField('sublevel'):
            print('CRIU sublevel %s' % resp.version.sublevel)
        if resp.version.HasField('extra'):
            print('CRIU extra %s' % resp.version.extra)
        if resp.version.HasField('name'):
            print('CRIU name %s' % resp.version.name)
    else:
        print('Fail')
        sys.exit(-1)
