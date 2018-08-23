# Same as libcriu for C.

import socket
import errno
import fcntl
import os
import struct

import pycriu.rpc_pb2 as rpc

class _criu_comm:
	"""
	Base class for communication classes.
	"""
	COMM_SK		= 0
	COMM_FD		= 1
	COMM_BIN	= 2
	comm_type	= None
	comm		= None
	sk		= None

	def connect(self, daemon):
		"""
		Connect to criu and return socket object.
		daemon -- is for whether or not criu should daemonize if executing criu from binary(comm_bin).
		"""
		pass

	def disconnect(self):
		"""
		Disconnect from criu.
		"""
		pass


class _criu_comm_sk(_criu_comm):
	"""
	Communication class for unix socket.
	"""
	def __init__(self, sk_path):
		self.comm_type = self.COMM_SK
		self.comm = sk_path

	def connect(self, daemon):
		self.sk = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
		self.sk.connect(self.comm)

		return self.sk

	def disconnect(self):
		self.sk.close()


class _criu_comm_fd(_criu_comm):
	"""
	Communication class for file descriptor.
	"""
	def __init__(self, fd):
		self.comm_type = self.COMM_FD
		self.comm = fd

	def connect(self, daemon):
		self.sk = socket.fromfd(self.comm, socket.AF_UNIX, socket.SOCK_SEQPACKET)

		return self.sk

	def disconnect(self):
		self.sk.close()

class _criu_comm_bin(_criu_comm):
	"""
	Communication class for binary.
	"""
	def __init__(self, bin_path):
		self.comm_type = self.COMM_BIN
		self.comm = bin_path
		self.swrk = None
		self.daemon = None

	def connect(self, daemon):
		# Kind of the same thing we do in libcriu
		css = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
		flags = fcntl.fcntl(css[1], fcntl.F_GETFD)
		fcntl.fcntl(css[1], fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
		flags = fcntl.fcntl(css[0], fcntl.F_GETFD)
		fcntl.fcntl(css[0], fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)

		self.daemon = daemon

		p = os.fork()

		if p == 0:
			def exec_criu():
				os.close(0)
				os.close(1)
				os.close(2)

				css[0].send(struct.pack('i', os.getpid()))
				os.execv(self.comm, [self.comm, 'swrk', "%d" % css[0].fileno()])
				os._exit(1)

			if daemon:
				# Python has no daemon(3) alternative,
				# so we need to mimic it ourself.
				p = os.fork()

				if p == 0:
					os.setsid()

					exec_criu()
				else:
					os._exit(0)
			else:
				exec_criu()
		else:
			if daemon:
				os.waitpid(p, 0)

		css[0].close()
		self.swrk = struct.unpack('i', css[1].recv(4))[0]
		self.sk = css[1]

		return self.sk

	def disconnect(self):
		self.sk.close()
		if not self.daemon:
			os.waitpid(self.swrk, 0)


class CRIUException(Exception):
	"""
	Exception class for handling and storing criu errors.
	"""
	typ = None
	_str = None

	def __str__(self):
		return self._str


class CRIUExceptionInternal(CRIUException):
	"""
	Exception class for handling and storing internal errors.
	"""
	def __init__(self, typ, s):
		self.typ = typ
		self._str = "%s failed with internal error: %s" % (rpc.criu_req_type.Name(self.typ), s)


class CRIUExceptionExternal(CRIUException):
	"""
	Exception class for handling and storing criu RPC errors.
	"""

	def __init__(self, req_typ, resp_typ, errno):
		self.typ = req_typ
		self.resp_typ = resp_typ
		self.errno = errno
		self._str = self._gen_error_str()

	def _gen_error_str(self):
		s = "%s failed: " % (rpc.criu_req_type.Name(self.typ), )

		if self.typ != self.resp_typ:
			s += "Unexpected response type %d: " % (self.resp_typ, )

		s += "Error(%d): " % (self.errno, )

		if self.errno == errno.EBADRQC:
			s += "Bad options"

		if self.typ == rpc.DUMP:
			if self.errno == errno.ESRCH:
				s += "No process with such pid"

		if self.typ == rpc.RESTORE:
			if self.errno == errno.EEXIST:
				s += "Process with requested pid already exists"

		s += "Unknown"

		return s


class criu:
	"""
	Call criu through RPC.
	"""
	opts		= None #CRIU options in pb format

	_comm		= None #Communication method

	def __init__(self):
		self.use_binary('criu')
		self.opts = rpc.criu_opts()
		self.sk = None

	def use_sk(self, sk_name):
		"""
		Access criu using unix socket which that belongs to criu service daemon.
		"""
		self._comm = _criu_comm_sk(sk_name)

	def use_fd(self, fd):
		"""
		Access criu using provided fd.
		"""
		self._comm = _criu_comm_fd(fd)

	def use_binary(self, bin_name):
		"""
		Access criu by execing it using provided path to criu binary.
		"""
		self._comm = _criu_comm_bin(bin_name)

	def _send_req_and_recv_resp(self, req):
		"""
		As simple as send request and receive response.
		"""
		# In case of self-dump we need to spawn criu swrk detached
		# from our current process, as criu has a hard time separating
		# process resources from its own if criu is located in a same
		# process tree it is trying to dump.
		daemon = False
		if req.type == rpc.DUMP and not req.opts.HasField('pid'):
			daemon = True

		try:
			if not self.sk:
				s = self._comm.connect(daemon)
			else:
				s = self.sk

			if req.keep_open:
				self.sk = s

			s.send(req.SerializeToString())

			buf = s.recv(len(s.recv(1, socket.MSG_TRUNC | socket.MSG_PEEK)))

			if not req.keep_open:
				self._comm.disconnect()

			resp = rpc.criu_resp()
			resp.ParseFromString(buf)
		except Exception as e:
			raise CRIUExceptionInternal(req.type, str(e))

		return resp

	def check(self):
		"""
		Checks whether the kernel support is up-to-date.
		"""
		req		= rpc.criu_req()
		req.type	= rpc.CHECK

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

	def dump(self):
		"""
		Checkpoint a process/tree identified by opts.pid.
		"""
		req 		= rpc.criu_req()
		req.type	= rpc.DUMP
		req.opts.MergeFrom(self.opts)

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

		return resp.dump

	def pre_dump(self):
		"""
		Checkpoint a process/tree identified by opts.pid.
		"""
		req 		= rpc.criu_req()
		req.type	= rpc.PRE_DUMP
		req.opts.MergeFrom(self.opts)

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

		return resp.dump

	def restore(self):
		"""
		Restore a process/tree.
		"""
		req		= rpc.criu_req()
		req.type	= rpc.RESTORE
		req.opts.MergeFrom(self.opts)

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

		return resp.restore

	def page_server_chld(self):
		req		= rpc.criu_req()
		req.type	= rpc.PAGE_SERVER_CHLD
		req.opts.MergeFrom(self.opts)
		req.keep_open   = True

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

		return resp.ps

	def wait_pid(self, pid):
		req		= rpc.criu_req()
		req.type	= rpc.WAIT_PID
		req.pid	 = pid

		resp = self._send_req_and_recv_resp(req)

		if not resp.success:
			raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

		return resp.status
