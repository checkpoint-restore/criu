#!/usr/bin/env python3
import errno
import os
import signal
import socket
import struct
import sys
import time
from contextlib import ExitStack
from unittest import mock

# Add ../../../lib so we can import pycriu
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import pycriu  # noqa: E402
from pycriu.criu import CRIUExceptionInternal  # noqa: E402
from pycriu.criu import criu as criu_class  # noqa: E402


def make_req(criu, keep_open):
    req = pycriu.rpc.criu_req(type=pycriu.rpc.CHECK, keep_open=keep_open)
    req.opts.MergeFrom(criu.opts)
    return req


def fail(msg):
    print("FAIL: %s" % msg)
    return 1


def main():
    # A failed keep_open request closes the connection, so the next
    # request reconnects instead of reusing it.
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    criu = criu_class()
    criu.use_fd(client.fileno())
    req = make_req(criu, True)
    server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                     success=False).SerializeToString())
    resp = criu._send_req_and_recv_resp(req)
    if resp.success:
        return fail("failed keep_open request returned success")
    if criu.sk is not None:
        return fail("failed keep_open request kept the socket cached")
    if server.recv(4096) != req.SerializeToString():
        return fail("server got a different request")
    req = make_req(criu, False)
    server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                     success=True).SerializeToString())
    resp = criu._send_req_and_recv_resp(req)
    if not resp.success:
        return fail("request after failed keep_open did not reconnect")
    server.close()
    client.close()

    # A normal request closes a socket kept by a keep_open request.
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    criu = criu_class()
    criu.use_fd(client.fileno())
    req = make_req(criu, True)
    server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                     success=True).SerializeToString())
    criu._send_req_and_recv_resp(req)
    if criu.sk is None:
        return fail("successful keep_open request did not keep the socket")
    req = make_req(criu, False)
    server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                     success=True).SerializeToString())
    criu._send_req_and_recv_resp(req)
    if criu.sk is not None:
        return fail("normal request left the closed socket cached")

    # A broken cached socket is dropped after an internal error.
    req = make_req(criu, True)
    server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                     success=True).SerializeToString())
    criu._send_req_and_recv_resp(req)
    if criu.sk is None:
        return fail("successful keep_open request did not keep the socket")
    criu.sk.close()
    try:
        criu._send_req_and_recv_resp(make_req(criu, False))
        return fail("request on a broken socket did not raise")
    except CRIUExceptionInternal:
        # Expected: the broken socket raises an internal error.
        pass
    if criu.sk is not None:
        return fail("broken socket stayed cached after the error")
    server.close()
    client.close()

    # Receive and parsing errors close and clear a cached connection.
    for response in (None, b"\x80"):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            criu = criu_class()
            criu.use_fd(client.fileno())
            server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                             success=True).SerializeToString())
            criu._send_req_and_recv_resp(make_req(criu, True))
            transport = criu.sk
            transport.settimeout(0.1)
            if response is not None:
                server.send(response)
            try:
                criu._send_req_and_recv_resp(make_req(criu, True))
                return fail("receive or parsing error did not raise")
            except CRIUExceptionInternal:
                pass
            if criu.sk is not None or criu._comm.sk is not None:
                return fail("receive or parsing error kept the socket cached")
            if transport.fileno() != -1:
                return fail("receive or parsing error left the socket open")

    # Cleanup must preserve the original request failure.
    for error in (OSError(errno.EIO, "transport failed"), KeyboardInterrupt(), SystemExit(42)):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            criu = criu_class()
            criu.use_fd(client.fileno())
            server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                             success=True).SerializeToString())
            criu._send_req_and_recv_resp(make_req(criu, True))
            transport = criu.sk
            disconnect = criu._comm.disconnect

            def fail_disconnect():
                disconnect()
                raise OSError("cleanup failed")

            with mock.patch.object(socket.socket, "recv_into", side_effect=error):
                with mock.patch.object(criu._comm, "disconnect", side_effect=fail_disconnect):
                    try:
                        criu._send_req_and_recv_resp(make_req(criu, False))
                        return fail("request failure did not raise")
                    except (CRIUExceptionInternal, KeyboardInterrupt, SystemExit) as caught:
                        if isinstance(error, Exception):
                            if not isinstance(caught, CRIUExceptionInternal):
                                return fail("cleanup error replaced the transport error")
                            if str(error) not in str(caught):
                                return fail("internal error did not preserve the transport error")
                        elif caught is not error:
                            return fail("cleanup changed the cancellation exception")
            if criu.sk is not None or criu._comm.sk is not None:
                return fail("request failure kept the socket cached")
            if transport.fileno() != -1:
                return fail("request failure left the socket open")

    # A successful response still wraps a failure to close its transport.
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server:
        criu = criu_class()
        criu.use_fd(client.fileno())
        server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                         success=True).SerializeToString())
        criu._send_req_and_recv_resp(make_req(criu, True))
        transport = criu.sk
        server.send(pycriu.rpc.criu_resp(type=pycriu.rpc.CHECK,
                                         success=True).SerializeToString())
        disconnect = criu._comm.disconnect
        error = OSError(errno.EIO, "cleanup failed")

        def fail_successful_disconnect():
            disconnect()
            raise error

        with mock.patch.object(criu._comm, "disconnect",
                               side_effect=fail_successful_disconnect) as cleanup:
            try:
                criu._send_req_and_recv_resp(make_req(criu, False))
                return fail("successful response ignored a cleanup error")
            except CRIUExceptionInternal as caught:
                if str(error) not in str(caught):
                    return fail("internal error did not preserve the cleanup error")
            if cleanup.call_count != 1:
                return fail("successful request retried a failed disconnect")
        if criu.sk is not None or criu._comm.sk is not None:
            return fail("successful request kept the socket cached after cleanup failed")
        if transport.fileno() != -1:
            return fail("successful request left the socket open after cleanup failed")

    # A failed service connection cleans up its socket.
    criu = criu_class()
    criu.use_sk("no-such-dir/service.socket")
    try:
        criu._comm.connect(False)
        return fail("connect to a missing socket did not raise")
    except FileNotFoundError:
        # Expected: there is no socket to connect to.
        pass
    if criu._comm.sk is not None:
        return fail("failed connect kept the socket")

    # A request to a binary that exits without serving reaps the child.
    criu = criu_class()
    criu.use_binary("/bin/true")
    try:
        criu._send_req_and_recv_resp(make_req(criu, False))
    except CRIUExceptionInternal:
        # Expected: the binary exits before it can serve.
        pass
    else:
        return fail("request to a dead binary did not raise")
    try:
        os.waitpid(-1, os.WNOHANG)
        return fail("request to a dead binary left an unreaped child")
    except ChildProcessError:
        # No unreaped child left: the request already reaped it.
        pass

    # A failed PID handshake closes both sockets and waits only for the
    # direct child, including in daemon mode.
    for daemon, error in ((False, None), (True, None),
                          (False, KeyboardInterrupt()), (True, KeyboardInterrupt()),
                          (False, SystemExit(42)), (True, SystemExit(42))):
        comm = criu_class()._comm
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(socket, "socketpair",
                                                        return_value=(client, server)))
                waitpid = patches.enter_context(mock.patch.object(os, "waitpid", wraps=os.waitpid))
                if error is not None:
                    patches.enter_context(mock.patch.object(socket.socket, "recv", side_effect=error))
                # connect() calls getpid() only in the worker child.
                patches.enter_context(mock.patch.object(os, "getpid", side_effect=lambda: os._exit(0)))
                try:
                    comm.connect(daemon)
                    return fail("failed worker handshake did not raise")
                except (struct.error, KeyboardInterrupt, SystemExit) as caught:
                    if error is None:
                        if not isinstance(caught, struct.error):
                            return fail("failed worker handshake raised a different error")
                    elif caught is not error:
                        return fail("handshake cleanup changed the cancellation exception")
                if waitpid.call_count != 1:
                    return fail("worker handshake waited for the same child twice or not at all")
            if client.fileno() != -1 or server.fileno() != -1:
                return fail("failed worker handshake left a socket open")
        try:
            os.waitpid(-1, os.WNOHANG)
            return fail("failed worker handshake left an unreaped child")
        except ChildProcessError:
            pass

    # disconnect() accepts a child the caller reaped itself.
    comm = criu_class()._comm
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    comm.daemon = False
    comm.swrk = pid
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as transport:
        comm.sk = transport
        try:
            comm.disconnect()
            comm.disconnect()
        except ChildProcessError:
            return fail("disconnect raised for an already reaped child")
        if transport.fileno() != -1:
            return fail("disconnect left the reaped child's socket open")
    if comm.swrk is not None:
        return fail("disconnect kept the reaped child pid")

    # disconnect() accepts a child the kernel reaped because the caller
    # ignores SIGCHLD.
    old_handler = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        for _ in range(100):
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break
            time.sleep(0.05)
        else:
            return fail("kernel did not reap the child with SIGCHLD ignored")
        comm = criu_class()._comm
        comm.daemon = False
        comm.swrk = pid
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as transport:
            comm.sk = transport
            try:
                comm.disconnect()
            except ChildProcessError:
                return fail("disconnect raised with SIGCHLD ignored")
            if transport.fileno() != -1:
                return fail("disconnect left the socket open with SIGCHLD ignored")
        if comm.swrk is not None:
            return fail("disconnect kept the child pid with SIGCHLD ignored")

        # Both connection modes must also accept SIGCHLD being ignored.
        for daemon in (False, True):
            comm = criu_class()._comm
            comm.comm = "/bin/true"
            comm.connect(daemon)
            comm.disconnect()
    finally:
        signal.signal(signal.SIGCHLD, old_handler)

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
