#!/usr/bin/python

import socket, os, sys
import rpc_pb2 as rpc
import argparse

parser = argparse.ArgumentParser(
    description="Test ability to restore a process from images using CRIU RPC")
parser.add_argument('socket', type=str, help="CRIU service socket")
parser.add_argument('dir',
                    type=str,
                    help="Directory where CRIU images could be found")

args = vars(parser.parse_args())

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])

# Create criu msg, set it's type to dump request
# and set dump options. Checkout more options in protobuf/rpc.proto
req = rpc.criu_req()
req.type = rpc.RESTORE
req.opts.images_dir_fd = os.open(args['dir'], os.O_DIRECTORY)
# As the dumped process is running with setsid this should not
# be necessary. There seems to be a problem for this testcase
# in combination with alpine's setsid.
# The dump is now done with -j and the restore also.
req.opts.shell_job = True

# Send request
s.send(req.SerializeToString())

# Recv response
resp = rpc.criu_resp()
MAX_MSG_SIZE = 1024
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

if resp.type != rpc.RESTORE:
    print('Unexpected msg type')
    sys.exit(-1)
else:
    if resp.success:
        print('Restore success')
    else:
        print('Restore fail')
        sys.exit(-1)
    print("PID of the restored program is %d\n" % (resp.restore.pid))
