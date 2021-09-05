#!/usr/bin/env python

import argparse
import os
import signal
import socket
import time
import sys
import subprocess

criu_bin = '../../criu/criu'


def mix(nr_tasks, nr_pipes):
    # Returned is the list of combinations.
    # Each combination is the lists of pipe descriptors.
    # Each pipe descriptor is a 2-elemtn tuple, that contains values
    # for R and W ends of pipes, each being a bit-field denoting in
    # which tasks the respective end should be opened or not.

    # First -- make a full set of combinations for a single pipe.
    max_idx = 1 << nr_tasks
    pipe_mix = [[(r, w)] for r in range(0, max_idx) for w in range(0, max_idx)]

    # Now, for every pipe throw another one into the game making
    # all possible combinations of what was seen before with the
    # newbie.
    pipes_mix = pipe_mix
    for t in range(1, nr_pipes):
        pipes_mix = [o + n for o in pipes_mix for n in pipe_mix]

    return pipes_mix


# Called by a test sub-process. It just closes the not needed ends
# of pipes and sleeps waiting for death.
def make_pipes(task_nr, nr_pipes, pipes, comb, status_pipe):
    print('\t\tMake pipes for %d' % task_nr)
    # We need to make sure that pipes have their
    # ends according to comb for task_nr

    for i in range(0, nr_pipes):
        # Read end
        if not (comb[i][0] & (1 << task_nr)):
            os.close(pipes[i][0])
        # Write end
        if not (comb[i][1] & (1 << task_nr)):
            os.close(pipes[i][1])

    os.write(status_pipe, '0')
    os.close(status_pipe)
    while True:
        time.sleep(100)


def get_pipe_ino(pid, fd):
    try:
        return os.stat('/proc/%d/fd/%d' % (pid, fd)).st_ino
    except:
        return None


def get_pipe_rw(pid, fd):
    for l in open('/proc/%d/fdinfo/%d' % (pid, fd)):
        if l.startswith('flags:'):
            f = l.split(None, 1)[1][-2]
            if f == '0':
                return 0  # Read
            elif f == '1':
                return 1  # Write
            break

    raise Exception('Unexpected fdinfo contents')


def check_pipe_y(pid, fd, rw, inos):
    ino = get_pipe_ino(pid, fd)
    if ino is None:
        return 'missing '
    if not inos.has_key(fd):
        inos[fd] = ino
    elif inos[fd] != ino:
        return 'wrong '
    mod = get_pipe_rw(pid, fd)
    if mod != rw:
        return 'badmode '
    return None


def check_pipe_n(pid, fd):
    ino = get_pipe_ino(pid, fd)
    if ino is None:
        return None
    else:
        return 'present '


def check_pipe_end(kids, fd, comb, rw, inos):
    t_nr = 0
    for t_pid in kids:
        if comb & (1 << t_nr):
            res = check_pipe_y(t_pid, fd, rw, inos)
        else:
            res = check_pipe_n(t_pid, fd)
        if res is not None:
            return res + 'kid(%d)' % t_nr
        t_nr += 1
    return None


def check_pipe(kids, fds, comb, inos):
    for e in (0, 1):  # 0 == R, 1 == W, see get_pipe_rw()
        res = check_pipe_end(kids, fds[e], comb[e], e, inos)
        if res is not None:
            return res + 'end(%d)' % e
    return None


def check_pipes(kids, pipes, comb):
    # Kids contain pids
    # Pipes contain pipe FDs
    # Comb contain list of pairs of bits for RW ends
    p_nr = 0
    p_inos = {}
    for p_fds in pipes:
        res = check_pipe(kids, p_fds, comb[p_nr], p_inos)
        if res is not None:
            return res + 'pipe(%d)' % p_nr
        p_nr += 1

    return None


# Run by test main process. It opens pipes, then forks kids that
# will contain needed pipe ends, then report back that it's ready
# and waits for a signal (unix socket message) to start checking
# the kids' FD tables.
def make_comb(comb, opts, status_pipe):
    print('\tMake pipes')
    # 1st -- make needed pipes
    pipes = []
    for p in range(0, opts.pipes):
        pipes.append(os.pipe())

    # Fork the kids that'll make pipes
    kc_pipe = os.pipe()
    kids = []
    for t in range(0, opts.tasks):
        pid = os.fork()
        if pid == 0:
            os.close(status_pipe)
            os.close(kc_pipe[0])
            make_pipes(t, opts.pipes, pipes, comb, kc_pipe[1])
            sys.exit(1)
        kids.append(pid)

    os.close(kc_pipe[1])
    for p in pipes:
        os.close(p[0])
        os.close(p[1])

    # Wait for kids to get ready
    k_res = ''
    while True:
        v = os.read(kc_pipe[0], 16)
        if v == '':
            break
        k_res += v
    os.close(kc_pipe[0])

    ex_code = 1
    if k_res == '0' * opts.tasks:
        print('\tWait for C/R')
        cmd_sk = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        cmd_sk.bind('\0CRIUPCSK')

        # Kids are ready, so is socket for kicking us. Notify the
        # parent task that we are good to go.
        os.write(status_pipe, '0')
        os.close(status_pipe)
        v = cmd_sk.recv(16)
        if v == '0':
            print('\tCheck pipes')
            res = check_pipes(kids, pipes, comb)
            if res is None:
                ex_code = 0
            else:
                print('\tFAIL %s' % res)

    # Just kill kids, all checks are done by us, we don't need'em any more
    for t in kids:
        os.kill(t, signal.SIGKILL)
        os.waitpid(t, 0)

    return ex_code


def cr_test(pid):
    print('C/R test')
    img_dir = 'pimg_%d' % pid
    try:
        os.mkdir(img_dir)
        subprocess.check_call([
            criu_bin, 'dump', '-t',
            '%d' % pid, '-D', img_dir, '-o', 'dump.log', '-v4', '-j'
        ])
    except:
        print('`- dump fail')
        return False

    try:
        os.waitpid(pid, 0)
        subprocess.check_call([
            criu_bin, 'restore', '-D', img_dir, '-o', 'rst.log', '-v4', '-j',
            '-d', '-S'
        ])
    except:
        print('`- restore fail')
        return False

    return True


def run(comb, opts):
    print('Checking %r' % comb)
    cpipe = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(cpipe[0])
        ret = make_comb(comb, opts, cpipe[1])
        sys.exit(ret)

    # Wait for the main process to get ready
    os.close(cpipe[1])
    res = os.read(cpipe[0], 16)
    os.close(cpipe[0])

    if res == '0':
        res = cr_test(pid)

        print('Wake up test')
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        if res:
            res = '0'
        else:
            res = 'X'
        try:
            # Kick the test to check its state
            s.sendto(res, '\0CRIUPCSK')
        except:
            # Restore might have failed or smth else happened
            os.kill(pid, signal.SIGKILL)
        s.close()

    # Wait for the guy to exit and get the result (PASS/FAIL)
    p, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st):
        st = os.WEXITSTATUS(st)

    print('Done (%d, pid == %d)' % (st, pid))
    return st == 0


p = argparse.ArgumentParser("CRIU test suite")
p.add_argument("--tasks", help="Number of tasks", default='2')
p.add_argument("--pipes", help="Number of pipes", default='2')
opts = p.parse_args()
opts.tasks = int(opts.tasks)
opts.pipes = int(opts.pipes)

pipe_combs = mix(opts.tasks, opts.pipes)

for comb in pipe_combs:
    if not run(comb, opts):
        print('FAIL')
        break
else:
    print('PASS')
