#!/usr/bin/env python2

from __future__ import print_function
import sys, socket
import hashlib

sk = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)

s = sys.stdin.read()
ret = sk.send(s)
print("%s: send() -> %d" % (sys.argv[1], ret), file=sys.stderr)
sk.shutdown(socket.SHUT_WR)
m = hashlib.md5()
while True:
    s = sk.recv((1 << 20) * 10)
    if not s:
        break
    print("%s: recv() -> %d" % (sys.argv[1], len(s)), file=sys.stderr)
    m.update(s)
print(repr(m.hexdigest()))
