# Same as libcriu for C.

import socket
import errno
import fcntl
import os
import struct

import pycriu.rpc_pb2 as rpc

CR_DEFAULT_SERVICE_ADDRESS = "./criu_service.socket"

class _criu_comm:
    """
    Base class for communication classes.
    """
    COMM_SK = 0
    COMM_FD = 1
    COMM_BIN = 2
    comm_type = None
    comm = None
    sk = None

    def connect(self, daemon):
        """
        Connect to criu and return socket object.
        daemon -- is for whether or not criu should daemonize if executing criu from binary(comm_bin).
        """
        pass

    def disconnect(self, wait=True):
        """
        Disconnect from criu.
        wait -- wait for a binary-mode worker to exit.
        With wait=False, a worker that is still running is not stopped, and
        an exited worker may remain a zombie until a later RPC call reaps
        it. When no pidfd is available, if another child reaper consumes its
        exit status, a reused PID can make a later check target an
        unrelated child.
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
        try:
            self.sk.connect(self.comm)
        except OSError as e:
            self.sk.close()
            self.sk = None
            if isinstance(e, FileNotFoundError):
                raise FileNotFoundError("Socket file not found.")
            if isinstance(e, ConnectionRefusedError):
                raise ConnectionRefusedError("Service not running.")
            raise

        return self.sk

    def disconnect(self, wait=True):
        if self.sk is None:
            return
        self.sk.close()
        self.sk = None


class _criu_comm_fd(_criu_comm):
    """
    Communication class for file descriptor.
    """

    def __init__(self, fd):
        self.comm_type = self.COMM_FD
        self.comm = fd

    def connect(self, daemon):
        self.sk = socket.fromfd(self.comm, socket.AF_UNIX,
                                socket.SOCK_SEQPACKET)

        return self.sk

    def disconnect(self, wait=True):
        if self.sk is None:
            return
        self.sk.close()
        self.sk = None


class _criu_comm_bin(_criu_comm):
    """
    Communication class for binary.
    """
    # Keep unfinished workers across connections and client objects.
    _pending_workers = []

    def __init__(self, bin_path):
        self.comm_type = self.COMM_BIN
        self.comm = bin_path
        self.swrk = None
        self._pidfd = None
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
                try:
                    os.close(0)
                    os.close(1)
                    os.close(2)

                    pid = os.getpid()
                    message = struct.pack('i', pid)
                    # Open the handle in the worker so it cannot identify
                    # a replacement process if the worker is reaped early.
                    pidfd = None if daemon else self._open_pidfd(pid)
                    if pidfd is None:
                        css[0].send(message)
                    else:
                        try:
                            css[0].sendmsg([message], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                       struct.pack('i', pidfd))])
                        finally:
                            os.close(pidfd)
                    os.execvp(self.comm,
                              [self.comm, 'swrk',
                               "%d" % css[0].fileno()])
                finally:
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
                try:
                    os.waitpid(p, 0)
                except ChildProcessError:
                    # The intermediate child exits right after the second
                    # fork and is already reaped, e.g. by the kernel when
                    # the caller ignores SIGCHLD.
                    pass

        css[0].close()
        try:
            pid_size = struct.calcsize('i')
            if daemon:
                message = css[1].recv(pid_size)
            else:
                message, ancillary, _, _ = css[1].recvmsg(
                    pid_size, socket.CMSG_SPACE(pid_size), socket.MSG_CMSG_CLOEXEC)
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        self._pidfd, = struct.unpack('i', data)
            self.swrk, = struct.unpack('i', message)
        except BaseException:
            css[1].close()
            # Daemon mode already reaped the intermediate child.
            if not daemon:
                worker = (p, self._pidfd)
                self._pidfd = None
                try:
                    self._wait_worker(worker)
                finally:
                    self._close_worker(worker)
            raise
        self.sk = css[1]

        return self.sk

    def disconnect(self, wait=True):
        transport, self.sk = self.sk, None
        worker = None if self.daemon or not self.swrk else (self.swrk, self._pidfd)
        self._pidfd = None
        reaped = None
        try:
            if transport is not None:
                transport.close()
            if worker is not None:
                reaped = self._wait_worker(worker, wait=wait)
        finally:
            if worker is not None:
                if reaped is False:
                    self._pending_workers.append(worker)
                else:
                    self._close_worker(worker)
        self.swrk = None

    @staticmethod
    def _open_pidfd(pid):
        """
        Return a pidfd for the worker, or None to fall back to its PID.
        A pidfd keeps referring to this worker after it is reaped, so a
        later check cannot reap an unrelated child that reuses the PID.
        """
        if not hasattr(os, "pidfd_open") or not hasattr(os, "P_PIDFD"):
            return None
        try:
            pidfd = os.pidfd_open(pid)
        except OSError:
            # The running kernel or process may not allow pidfds.
            return None
        try:
            # Linux 5.3 has pidfd_open() but no waitid(P_PIDFD).
            os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            # P_PIDFD is supported, but the worker cannot wait on itself.
            pass
        except OSError:
            os.close(pidfd)
            return None
        except BaseException:
            os.close(pidfd)
            raise
        return pidfd

    @staticmethod
    def _wait_worker(worker, wait=True):
        pid, pidfd = worker
        options = 0
        if not wait:
            options = os.WNOHANG
        try:
            if pidfd is None:
                return os.waitpid(pid, options)[0] != 0
            return os.waitid(os.P_PIDFD, pidfd, os.WEXITED | options) is not None
        except ChildProcessError:
            # The child was already reaped, e.g. by the kernel when
            # the caller ignores SIGCHLD.
            return True

    @staticmethod
    def _close_worker(worker):
        pidfd = worker[1]
        if pidfd is not None:
            os.close(pidfd)

    @classmethod
    def _reap_workers(cls):
        for worker in cls._pending_workers[:]:
            try:
                # Take the worker so that another request cannot wait on
                # its pidfd after this one closes it.
                cls._pending_workers.remove(worker)
            except ValueError:
                # Another request is already checking this worker.
                continue
            retry = True
            try:
                retry = not cls._wait_worker(worker, wait=False)
                if not retry:
                    cls._close_worker(worker)
            except OSError as error:
                # Retry a failed wait on later RPCs unless the descriptor is gone.
                if error.errno == errno.EBADF:
                    retry = False
            finally:
                if retry:
                    cls._pending_workers.append(worker)


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
        self._str = "%s failed with internal error: %s" % (
            rpc.criu_req_type.Name(self.typ), s)


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

        # Most errors don't set cr_errno, so there is nothing to decode.
        if self.errno == 0:
            return s + "see the criu log for details"

        s += "Error(%d): " % (self.errno, )

        if self.errno == errno.EBADRQC:
            s += "Bad options"

        elif self.typ == rpc.DUMP and self.errno == errno.ESRCH:
            s += "No process with such pid"

        elif self.typ == rpc.RESTORE and self.errno == errno.EEXIST:
            s += "Process with requested pid already exists"

        else:
            s += "Unknown"

        return s


class criu:
    """
    Call criu through RPC.
    """
    opts = None  #CRIU options in pb format

    _comm = None  #Communication method

    def __init__(self):
        self.use_binary('criu')
        # images_dir_fd is required field with default value of -1
        self.opts = rpc.criu_opts(images_dir_fd=-1)
        self.sk = None

    def use_sk(self, sk_name=CR_DEFAULT_SERVICE_ADDRESS):
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
        If an RPC fails after connecting, the criu process may still be
        running when the error is raised. Later requests check for its exit
        and reap it.
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
        if req.type == rpc.DUMP and (not req.opts.HasField('pid') or req.opts.pid == os.getpid()):
            daemon = True

        try:
            _criu_comm_bin._reap_workers()
            if not self.sk:
                s = self._comm.connect(daemon)
            else:
                s = self.sk

            s.send(req.SerializeToString())

            # With MSG_TRUNC, the real message length is returned.
            size = s.recv_into(bytearray(1), 1, socket.MSG_TRUNC | socket.MSG_PEEK)
            buf = s.recv(size)

            resp = rpc.criu_resp()
            resp.ParseFromString(buf)
        except BaseException as e:
            self.sk = None
            try:
                self._comm.disconnect(wait=False)
            except Exception:
                # Preserve the request failure if cleanup also fails.
                pass
            if isinstance(e, Exception):
                raise CRIUExceptionInternal(req.type, str(e))
            raise

        if req.keep_open and resp.success:
            # Only a successful keep_open response starts a session;
            # criu may keep its side open after a failure, so do not
            # rely on the server closing it.
            self.sk = s
        else:
            self.sk = None
            try:
                self._comm.disconnect()
            except Exception as e:
                raise CRIUExceptionInternal(req.type, str(e))

        return resp

    def check(self):
        """
        Checks whether the kernel support is up-to-date.
        """
        req = rpc.criu_req()
        req.type = rpc.CHECK
        req.opts.MergeFrom(self.opts)

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

    def dump(self):
        """
        Checkpoint a process/tree identified by opts.pid.
        """
        req = rpc.criu_req()
        req.type = rpc.DUMP
        req.opts.MergeFrom(self.opts)

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

        return resp.dump

    def pre_dump(self):
        """
        Checkpoint a process/tree identified by opts.pid.
        """
        req = rpc.criu_req()
        req.type = rpc.PRE_DUMP
        req.opts.MergeFrom(self.opts)

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

        return resp.dump

    def restore(self):
        """
        Restore a process/tree.
        """
        req = rpc.criu_req()
        req.type = rpc.RESTORE
        req.opts.MergeFrom(self.opts)

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

        return resp.restore

    def page_server_chld(self):
        req = rpc.criu_req()
        req.type = rpc.PAGE_SERVER_CHLD
        req.opts.MergeFrom(self.opts)
        req.keep_open = True

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

        return resp.ps

    def wait_pid(self, pid):
        req = rpc.criu_req()
        req.type = rpc.WAIT_PID
        req.pid = pid

        resp = self._send_req_and_recv_resp(req)

        if not resp.success:
            raise CRIUExceptionExternal(req.type, resp.type, resp.cr_errno)

        return resp.status
