#!/usr/bin/python
# Test criu errno

import socket, os, imp, sys, errno

p = os.getcwd()
sys.path.append(p)
import rpc_pb2 as rpc


# Prepare dir for images
class test:
	def __init__(self):
		imgs_path = "imgs_errno"
		if not os.path.exists(imgs_path):
			os.makedirs(imgs_path)
		self.imgs_fd = os.open(imgs_path, os.O_DIRECTORY)
		self.s = -1
		self._MAX_MSG_SIZE = 1024

	def connect(self):
		self.s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
		self.s.connect('criu_service.socket')

	def get_base_req(self):
		req			= rpc.criu_req()
		req.opts.log_level	= 4
		req.opts.images_dir_fd	= self.imgs_fd
		return req

	def send_req(self, req):
		self.connect()
		self.s.send(req.SerializeToString())

	def recv_resp(self):
		resp = rpc.criu_resp()
		resp.ParseFromString(self.s.recv(self._MAX_MSG_SIZE))
		return resp

	def check_resp(self, resp, typ, err):
		if resp.type != typ:
			raise Exception('Unexpected responce type ' + str(resp.type))

		if resp.success:
			raise Exception('Unexpected success = True')

		if err and resp.cr_errno != err:
			raise Exception('Unexpected cr_errno ' + str(resp.cr_errno))

	def no_process(self):
		print 'Try to dump unexisting process'
		# Get pid of non-existing process.
		# Suppose max_pid is not taken by any process.
		with open("/proc/sys/kernel/pid_max", "r") as f:
			pid = int(f.readline())
			try:
				os.kill(pid, 0)
			except OSError:
				pass
			else:
				raise Exception('max pid is taken')

		# Ask criu to dump non-existing process.
		req = self.get_base_req()
		req.type = rpc.DUMP
		req.opts.pid = pid

		self.send_req(req)
		resp = self.recv_resp()

		self.check_resp(resp, rpc.DUMP, errno.ESRCH)

		print 'Success'

	def process_exists(self):
		print 'Try to restore process which pid is already taken by other process'

		# Perform self-dump
		req = self.get_base_req()
		req.type		= rpc.DUMP
		req.opts.shell_job	= True
		req.opts.leave_running	= True

		self.send_req(req)
		resp = self.recv_resp()

		if resp.success != True:
			raise Exception('Self-dump failed')

		# Ask to restore process from images of ourselves
		req = self.get_base_req()
		req.type = rpc.RESTORE

		self.send_req(req)
		resp = self.recv_resp()

		self.check_resp(resp, rpc.RESTORE, errno.EEXIST)

		print 'Success'

	def bad_options(self):
		print 'Try to send criu invalid opts'

		# Subdirs are not allowed in log_file
		req = self.get_base_req()
		req.type = rpc.DUMP
		req.opts.log_file = "../file.log"

		self.send_req(req)
		resp = self.recv_resp()

		self.check_resp(resp, rpc.DUMP, errno.EBADRQC)

		print 'Success'

	def bad_request(self):
		print 'Try to send criu invalid request type'

		req = self.get_base_req()
		req.type = rpc.NOTIFY

		self.send_req(req)
		resp = self.recv_resp()

		self.check_resp(resp, rpc.EMPTY, None)

		print 'Success'

	def run(self):
		self.no_process()
		self.process_exists()
		self.bad_options()
		self.bad_request()

t = test()
t.run()
