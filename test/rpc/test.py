#!/usr/bin/python

import socket, os, imp, sys

p = os.getcwd()
sys.path.append(p)
import rpc_pb2 as rpc

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect('criu_service.socket')

# Create criu msg, set it's type to dump request
# and set dump options. Checkout more options in protobuf/rpc.proto
req			= rpc.criu_req()
req.type		= rpc.DUMP
req.opts.leave_running	= True
req.opts.shell_job	= True
req.opts.log_level	= 4

if not os.path.exists('imgs_py'):
	os.makedirs('imgs_py')

req.opts.images_dir_fd	= os.open('imgs_py', os.O_DIRECTORY)

# Send request
s.send(req.SerializeToString())

# Recv response
resp		= rpc.criu_resp()
MAX_MSG_SIZE	= 1024
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

if resp.type != rpc.DUMP:
	print 'Unexpected msg type'
	sys.exit(-1)
else:
	if resp.success:
		print 'Success'
	else:
		print 'Fail'
		sys.exit(-1)

	if resp.dump.restored:
		print 'Restored'
