#!/usr/bin/env python3
import os
import socket
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "../../../lib"))
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import pycriu  # noqa: E402


class ReceiveTests(unittest.TestCase):
    def test_receive_response(self):
        for size in (0, 8192):
            with self.subTest(size=size):
                client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with client, server:
                    client.settimeout(5)
                    server.settimeout(5)
                    criu = pycriu.criu()
                    criu.use_fd(client.fileno())
                    self.addCleanup(criu._comm.disconnect)
                    req = pycriu.rpc.criu_req(type=pycriu.rpc.CHECK)
                    req.opts.MergeFrom(criu.opts)
                    expected = pycriu.rpc.criu_resp(type=req.type, success=False,
                                                   cr_errmsg="x" * size)
                    server.send(expected.SerializeToString())

                    actual = criu._send_req_and_recv_resp(req)

                    self.assertEqual(actual, expected)
                    self.assertEqual(server.recv(1024), req.SerializeToString())

    def test_receive_multiple_responses(self):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            client.settimeout(5)
            server.settimeout(5)
            criu = pycriu.criu()
            criu.use_fd(client.fileno())
            self.addCleanup(criu._comm.disconnect)
            for keep_open in (True, False):
                req = pycriu.rpc.criu_req(type=pycriu.rpc.CHECK, keep_open=keep_open)
                req.opts.MergeFrom(criu.opts)
                expected = pycriu.rpc.criu_resp(type=req.type, success=True)
                server.send(expected.SerializeToString())

                self.assertEqual(criu._send_req_and_recv_resp(req), expected)
                self.assertEqual(server.recv(1024), req.SerializeToString())


if __name__ == "__main__":
    unittest.main()
