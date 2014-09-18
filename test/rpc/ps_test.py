#!/usr/bin/python

import socket, os, imp, sys

p = os.getcwd()
sys.path.append(p)
import rpc_pb2 as rpc

# Connect to service socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect('criu_service.socket')

# Start page-server
print 'Starting page-server'
req			= rpc.criu_req()
req.type		= rpc.PAGE_SERVER
req.opts.log_file	= 'page-server.log'
req.opts.log_level	= 4

if not os.path.exists('ps_test'):
	os.makedirs('ps_test')

req.opts.images_dir_fd	= os.open('ps_test', os.O_DIRECTORY)

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
s.connect('criu_service.socket')
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
