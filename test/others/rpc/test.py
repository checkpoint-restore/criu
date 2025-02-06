#!/usr/bin/python3

import socket, os, sys
import rpc_pb2 as rpc
import argparse

parser = argparse.ArgumentParser(
    description="Test dump/restore using CRIU RPC")
parser.add_argument('socket', type=str, help="CRIU service socket")
parser.add_argument('dir',
                    type=str,
                    help="Directory where CRIU images should be placed")

args = vars(parser.parse_args())

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])

# Create criu msg, set it's type to dump request
# and set dump options. Checkout more options in protobuf/rpc.proto
req = rpc.criu_req()
req.type = rpc.DUMP
req.opts.leave_running = True
req.opts.log_level = 4
req.opts.images_dir_fd = os.open(args['dir'], os.O_DIRECTORY)
req.opts.network_lock = rpc.SKIP

# Send request
s.send(req.SerializeToString())

# Recv response
resp = rpc.criu_resp()
MAX_MSG_SIZE = 1024
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

if resp.type != rpc.DUMP:
    print('Unexpected msg type')
    sys.exit(-1)
else:
    if resp.success:
        print('Success')
    else:
        print('Fail')
        sys.exit(-1)

    if resp.dump.restored:
        print('Restored')

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])

# Create criu msg, set it's type to dump request
# and set dump options. Checkout more options in protobuf/rpc.proto
req = rpc.criu_req()
req.type = rpc.VERSION

# Send request
s.send(req.SerializeToString())

# Recv response
resp = rpc.criu_resp()
MAX_MSG_SIZE = 1024
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

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
