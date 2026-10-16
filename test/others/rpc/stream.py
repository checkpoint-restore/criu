#!/usr/bin/python3

import argparse
import fcntl
import os
import socket
import sys

import rpc_pb2 as rpc
import subprocess

MAX_MSG_SIZE = 1024
IMG_FILE = 'img.criu'


def spawn_streamer(action, images_dir, img_file):
    progress_r, progress_w = os.pipe()
    fcntl.fcntl(progress_r, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    fcntl.fcntl(progress_w, fcntl.F_SETFD, 0)

    # The streamer works with pipes, hence cat on the other end.
    if action == 'capture':
        cmd = "criu-image-streamer --images-dir '%s' --progress-fd %d capture | cat > %s" % (
            images_dir, progress_w, img_file)
    else:
        cmd = "cat %s | criu-image-streamer --images-dir '%s' --progress-fd %d %s" % (
            img_file, images_dir, progress_w, action)

    log = open(os.path.join(images_dir, '%s.log' % action), 'w')
    p = subprocess.Popen(['bash', '-c', 'set -o pipefail; ' + cmd],
                         stderr=log, close_fds=False)
    log.close()
    os.close(progress_w)

    progress = os.fdopen(progress_r, 'r')
    if action == 'serve':
        progress.readline()
    if progress.readline().strip() != 'socket-init':
        p.kill()
        sys.exit('criu-image-streamer (%s) never opened its socket' % action)
    return p


def reap_streamer(p, action):
    if p.wait() != 0:
        sys.exit('criu-image-streamer (%s) exited with %d' % (action, p.returncode))


def rpc_call(sk_path, req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(sk_path)
    s.send(req.SerializeToString())
    resp = rpc.criu_resp()
    resp.ParseFromString(s.recv(MAX_MSG_SIZE))
    s.close()
    return resp


parser = argparse.ArgumentParser(
    description='Test streamed dump/restore using CRIU RPC')
parser.add_argument('service_socket', type=str, help='CRIU service socket')
parser.add_argument('dir', type=str, help='Directory the images are streamed through')
parser.add_argument('pid', type=int, help='PID of the process to dump')
args = vars(parser.parse_args())

images_dir = os.path.abspath(args['dir'])
img_file = os.path.join(images_dir, IMG_FILE)

streamer = spawn_streamer('capture', images_dir, img_file)

req = rpc.criu_req()
req.type = rpc.DUMP
req.opts.pid = args['pid']
req.opts.stream = True
req.opts.shell_job = True
req.opts.log_file = 'dump.log'
req.opts.log_level = 4
req.opts.images_dir_fd = os.open(images_dir, os.O_DIRECTORY)
req.opts.network_lock = rpc.SKIP

resp = rpc_call(args['service_socket'], req)
if resp.type != rpc.DUMP or not resp.success:
    sys.exit('Streamed dump over RPC failed')
print('Streamed dump success')

on_disk = sorted(f for f in os.listdir(images_dir) if f.endswith('.img'))
if on_disk:
    sys.exit('Images landed in the directory, not in the stream: %s' %
             ' '.join(on_disk))

reap_streamer(streamer, 'capture')

streamer = spawn_streamer('serve', images_dir, img_file)

req = rpc.criu_req()
req.type = rpc.RESTORE
req.opts.stream = True
req.opts.shell_job = True
req.opts.log_file = 'restore.log'
req.opts.log_level = 4
req.opts.images_dir_fd = os.open(images_dir, os.O_DIRECTORY)

resp = rpc_call(args['service_socket'], req)
if resp.type != rpc.RESTORE or not resp.success:
    sys.exit('Streamed restore over RPC failed')
print('Streamed restore success, pid %d' % resp.restore.pid)

reap_streamer(streamer, 'serve')

os.kill(resp.restore.pid, 9)
