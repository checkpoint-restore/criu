#!/usr/bin/python

import socket, os, imp, sys
import rpc_pb2 as rpc
import argparse

parser = argparse.ArgumentParser(description="Test page-server using CRIU RPC")
parser.add_argument('socket', type = str, help = "CRIU service socket")
parser.add_argument('dir', type = str, help = "Directory where CRIU images should be placed")

args = vars(parser.parse_args())

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])

# Start page-server
print 'Starting page-server'
req			= rpc.criu_req()
req.type		= rpc.PAGE_SERVER
req.opts.log_file	= 'page-server.log'
req.opts.log_level	= 4
req.opts.images_dir_fd	= os.open(args['dir'], os.O_DIRECTORY)

s.send(req.SerializeToString())

resp	= rpc.criu_resp()
MAX_MSG_SIZE = 1024
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

if resp.type != rpc.PAGE_SERVER:
	print 'Unexpected msg type'
	sys.exit(1)
else:
	if resp.success:
		# check if pid even exists
		try:
			os.kill(resp.ps.pid, 0)
		except OSError as err:
			if err.errno == errno.ESRCH:
				print 'No process with page-server pid %d' %(resp.ps.pid)
			else:
				print 'Can\'t check that process %d exists' %(resp.ps.pid)
				sys.exit(1)
		print 'Success, page-server pid %d started on port %u' %(resp.ps.pid, resp.ps.port)
	else:
		print 'Failed to start page-server'
		sys.exit(1)


# Perform self-dump
print 'Dumping myself using page-server'
req.type		= rpc.DUMP
req.opts.ps.port	= resp.ps.port
req.opts.log_file	= 'dump.log'
req.opts.shell_job	= True
req.opts.leave_running	= True

s.close()
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])
s.send(req.SerializeToString())

resp.ParseFromString(s.recv(MAX_MSG_SIZE))

if resp.type != rpc.DUMP:
	print 'Unexpected msg type'
	sys.exit(1)
else:
	if resp.success:
		print 'Success'
	else:
		print 'Fail'
		sys.exit(1)
