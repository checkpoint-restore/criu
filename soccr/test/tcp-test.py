#!/usr/bin/env python2

import os, sys, socket
import hashlib

sk = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)

s = sys.stdin.read()
ret = sk.send(s)
print >> sys.stderr, "%s: send() -> %d" % (sys.argv[1], ret)
sk.shutdown(socket.SHUT_WR)
m = hashlib.md5()
while True:
    s = sk.recv((1 << 20) * 10)
    if not s:
        break
    print >> sys.stderr, "%s: recv() -> %d" % (sys.argv[1], len(s))
    m.update(s)
print repr(m.hexdigest())
