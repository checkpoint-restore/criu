#!/usr/bin/env python

import sys
import os
import socket
import argparse
import subprocess
import signal
import fcntl
import stat

criu_bin = '../../criu/criu'

sk_type_s = {
    socket.SOCK_STREAM: "S",
    socket.SOCK_DGRAM: "D",
}

# Actions that can be done by test. Actions are not only syscall
# names to call, but also arguments with which to do it
#
# Each action consists of
# - arguments, e.g. type of socket, or socket id to work on
# - act() method which just generates an record
# - do() method, that actually does what's required
# - show() method to return the string description of what's done


def mk_socket(st, typ):
    st.sk_id += 1
    sk = sock(st.sk_id, typ)
    st.add_socket(sk)
    return sk


class act_socket:
    def __init__(self, typ):
        self.typ = typ

    def act(self, st):
        sk = mk_socket(st, self.typ)
        self.sk_id = sk.sk_id

    def do(self, st):
        sk = socket.socket(socket.AF_UNIX, self.typ, 0)
        st.real_sockets[self.sk_id] = sk

    def show(self):
        return 'socket(%s) = %d' % (sk_type_s[self.typ], self.sk_id)


class act_close:
    def __init__(self, sk_id):
        self.sk_id = sk_id

    def act(self, st):
        sk = st.get_socket(self.sk_id)
        st.del_socket(sk)
        for ic in sk.icons:
            sk = st.get_socket(ic)
            st.del_socket(sk)

    def do(self, st):
        sk = st.real_sockets.pop(self.sk_id)
        sk.close()

    def show(self):
        return 'close(%d)' % self.sk_id


class act_listen:
    def __init__(self, sk_id):
        self.sk_id = sk_id

    def act(self, st):
        sk = st.get_socket(self.sk_id)
        sk.listen = True

    def do(self, st):
        sk = st.real_sockets[self.sk_id]
        sk.listen(10)

    def show(self):
        return 'listen(%d)' % self.sk_id


class act_bind:
    def __init__(self, sk_id, name_id):
        self.sk_id = sk_id
        self.name_id = name_id

    def act(self, st):
        sk = st.get_socket(self.sk_id)
        sk.name = self.name_id

    def do(self, st):
        sk = st.real_sockets[self.sk_id]
        sk.bind(sock.real_name_for(self.name_id))

    def show(self):
        return 'bind(%d, $name-%d)' % (self.sk_id, self.name_id)


class act_connect:
    def __init__(self, sk_id, listen_sk_id):
        self.sk_id = sk_id
        self.lsk_id = listen_sk_id

    def act(self, st):
        sk = st.get_socket(self.sk_id)
        if st.sk_type == socket.SOCK_STREAM:
            lsk = st.get_socket(self.lsk_id)
            psk = mk_socket(st, socket.SOCK_STREAM)
            psk.visible = False
            sk.peer = psk.sk_id
            psk.peer = sk.sk_id
            psk.name = lsk.name
            lsk.icons.append(psk.sk_id)
            lsk.icons_seq += 1
        else:
            sk.peer = self.lsk_id
            psk = st.get_socket(self.lsk_id)
            psk.icons_seq += 1

    def do(self, st):
        sk = st.real_sockets[self.sk_id]
        sk.connect(sock.real_name_for(self.lsk_id))

    def show(self):
        return 'connect(%d, $name-%d)' % (self.sk_id, self.lsk_id)


class act_accept:
    def __init__(self, sk_id):
        self.sk_id = sk_id

    def act(self, st):
        lsk = st.get_socket(self.sk_id)
        iid = lsk.icons.pop(0)
        nsk = st.get_socket(iid)
        nsk.visible = True
        self.nsk_id = nsk.sk_id

    def do(self, st):
        sk = st.real_sockets[self.sk_id]
        nsk, ai = sk.accept()
        if self.nsk_id in st.real_sockets:
            raise Exception("SK ID conflict")
        st.real_sockets[self.nsk_id] = nsk

    def show(self):
        return 'accept(%d) = %d' % (self.sk_id, self.nsk_id)


class act_sendmsg:
    def __init__(self, sk_id, to_id):
        self.sk_id = sk_id
        self.to_id = to_id
        self.direct_send = None

    def act(self, st):
        sk = st.get_socket(self.sk_id)
        msg = (sk.sk_id, sk.outseq)
        self.msg_id = sk.outseq
        sk.outseq += 1
        psk = st.get_socket(self.to_id)
        psk.inqueue.append(msg)
        self.direct_send = (sk.peer == psk.sk_id)

    def do(self, st):
        sk = st.real_sockets[self.sk_id]
        msgv = act_sendmsg.msgval(self.msg_id)
        if self.direct_send:
            sk.send(msgv)
        else:
            sk.sendto(msgv, sock.real_name_for(self.to_id))

    def show(self):
        return 'send(%d, %d, $message-%d)' % (self.sk_id, self.to_id,
                                              self.msg_id)

    @staticmethod
    def msgval(msgid, pref=''):
        return '%sMSG%d' % (pref, msgid)


#
# Description of a socket
#
class sock:
    def __init__(self, sk_id, sock_type):
        # ID of a socket. Since states and sockets are cloned
        # while we scan the tree of states the only valid way
        # to address a socket is to find one by ID.
        self.sk_id = sk_id
        # The socket.SOCK_FOO value
        self.sk_type = sock_type
        # Sockets that haven't yet been accept()-ed are in the
        # state, but user cannot operate on them. Also this
        # invisibility contributes to state description since
        # connection to not accepted socket is not the same
        # as connection to accepted one.
        self.visible = True
        # The listen() was called.
        self.listen = False
        # The bind() was called. Also set by accept(), the name
        # inherits from listener.
        self.name = None
        # The connect() was called. Set on two sockets when the
        # connect() is called.
        self.peer = None
        # Progress on accepting connections. Used to check when
        # it's OK to close the socket (see comment below).
        self.icons_seq = 0
        # List of IDs of sockets that can be accept()-ed
        self.icons = []
        # Number to generate message contents.
        self.outseq = 0
        # Incoming queue of messages.
        self.inqueue = []

    def clone(self):
        sk = sock(self.sk_id, self.sk_type)
        sk.visible = self.visible
        sk.listen = self.listen
        sk.name = self.name
        sk.peer = self.peer
        sk.icons_seq = self.icons_seq
        sk.icons = list(self.icons)
        sk.outseq = self.outseq
        sk.inqueue = list(self.inqueue)
        return sk

    def get_actions(self, st):
        if not self.visible:
            return []

        if st.sk_type == socket.SOCK_STREAM:
            return self.get_stream_actions(st)
        else:
            return self.get_dgram_actions(st)

    def get_send_action(self, to, st):
        # However, if peer has a message from us at
        # the queue tail, sending a new one doesn't
        # really make sense
        want_msg = True
        if len(to.inqueue) != 0:
            lmsg = to.inqueue[-1]
            if lmsg[0] == self.sk_id:
                want_msg = False
        if want_msg:
            return [act_sendmsg(self.sk_id, to.sk_id)]
        else:
            return []

    def get_stream_actions(self, st):
        act_list = []

        # Any socket can be closed, but closing a socket
        # that hasn't contributed to some new states is
        # just waste of time, so we close only connected
        # sockets or listeners that has at least one
        # incoming connection pending or served

        if self.listen:
            if self.icons:
                act_list.append(act_accept(self.sk_id))
            if self.icons_seq:
                act_list.append(act_close(self.sk_id))
        elif self.peer:
            act_list.append(act_close(self.sk_id))
            # Connected sockets can send and receive messages
            # But receiving seem not to produce any new states,
            # so only sending
            # Also sending to a closed socket doesn't work
            psk = st.get_socket(self.peer, True)
            if psk:
                act_list += self.get_send_action(psk, st)
        else:
            for psk in st.sockets:
                if psk.listen and psk.name:
                    act_list.append(act_connect(self.sk_id, psk.sk_id))

            # Listen on not-bound socket is prohibited as
            # well as binding a listening socket
            if not self.name:
                # TODO: support for file paths (see real_name_for)
                # TODO: these names can overlap each other
                act_list.append(act_bind(self.sk_id, self.sk_id))
            else:
                act_list.append(act_listen(self.sk_id))

        return act_list

    def get_dgram_actions(self, st):
        act_list = []

        # Dgram socket can bind at any time
        if not self.name:
            act_list.append(act_bind(self.sk_id, self.sk_id))

        # Can connect to peer-less sockets
        for psk in st.sockets:
            if psk == self:
                continue
            if psk.peer is not None and psk.peer != self.sk_id:
                # Peer by someone else, can do nothing
                continue

            # Peer-less psk or having us as peer
            # We can connect to or send messages
            if psk.name and self.peer != psk.sk_id:
                act_list.append(act_connect(self.sk_id, psk.sk_id))

            if psk.name or self.peer == psk.sk_id:
                act_list += self.get_send_action(psk, st)

        if self.outseq != 0 or self.icons_seq != 0:
            act_list.append(act_close(self.sk_id))

        return act_list

    @staticmethod
    def name_of(sk):
        if not sk:
            return 'X'
        elif not sk.visible:
            return 'H'
        elif sk.name:
            return 'B'
        else:
            return 'A'

    @staticmethod
    def real_name_for(sk_id):
        return "\0" + "CRSK%d" % sk_id

    # The describe() generates a string that represents
    # a state of a socket. Called by state.describe(), see
    # comment there about what description is.
    def describe(self, st):
        dsc = '%s' % sk_type_s[self.sk_type]
        dsc += sock.name_of(self)

        if self.listen:
            dsc += 'L'
        if self.peer:
            psk = st.get_socket(self.peer, True)
            dsc += '-C%s' % sock.name_of(psk)
        if self.icons:
            i_dsc = ''
            for c in self.icons:
                psk = st.get_socket(c)
                psk = st.get_socket(psk.peer, True)
                i_dsc += sock.name_of(psk)
            dsc += '-I%s' % i_dsc
        if self.inqueue:
            from_set = set()
            for m in self.inqueue:
                from_set.add(m[0])
            q_dsc = ''
            for f in from_set:
                fsk = st.get_socket(f, True)
                q_dsc += sock.name_of(fsk)
            dsc += '-M%s' % q_dsc
        return dsc


class state:
    def __init__(self, max_sockets, sk_type):
        self.sockets = []
        self.sk_id = 0
        self.steps = []
        self.real_sockets = {}
        self.sockets_left = max_sockets
        self.sk_type = sk_type

    def add_socket(self, sk):
        self.sockets.append(sk)

    def del_socket(self, sk):
        self.sockets.remove(sk)

    def get_socket(self, sk_id, can_be_null=False):
        for sk in self.sockets:
            if sk.sk_id == sk_id:
                return sk

        if not can_be_null:
            raise Exception("%d socket not in list" % sk_id)

        return None

    def get_actions(self):
        act_list = []

        # Any socket in the state we can change it
        for sk in self.sockets:
            act_list += sk.get_actions(self)

        if self.sockets_left > 0:
            act_list.append(act_socket(self.sk_type))
            self.sockets_left -= 1

        return act_list

    def clone(self):
        nst = state(self.sockets_left, self.sk_type)
        for sk in self.sockets:
            nst.sockets.append(sk.clone())
        nst.sk_id = self.sk_id
        nst.steps = list(self.steps)
        return nst

    # Generates textual description of a state. Different states
    # may have same descriptions, e.g. if we have two sockets and
    # only one of them is in listen state, we don't care which
    # one in which. At the same time really different states
    # shouldn't map to the same string.
    def describe(self):
        sks = [x.describe(self) for x in self.sockets]
        sks = sorted(sks)
        return '_'.join(sks)


def set_nonblock(sk):
    fd = sk.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


CHK_FAIL_UNKNOWN = 10
CHK_FAIL_SOCKET = 11
CHK_FAIL_STAT = 12
CHK_FAIL_LISTEN = 13
CHK_FAIL_NAME = 14
CHK_FAIL_ACCEPT = 15
CHK_FAIL_RECV_0 = 16
CHK_FAIL_RECV_MIX = 17
CHK_FAIL_CONNECT = 18
CHK_FAIL_CONNECT2 = 19
CHK_FAIL_KILLED = 20
CHK_FAIL_DUMP = 21
CHK_FAIL_RESTORE = 22

CHK_PASS = 42

fail_desc = {
    CHK_FAIL_UNKNOWN: 'Aliens invaded the test',
    CHK_FAIL_LISTEN: 'Listen state lost on restore',
    CHK_FAIL_NAME: 'Name lost on restore',
    CHK_FAIL_ACCEPT: 'Incoming connection lost on restore',
    CHK_FAIL_RECV_0: 'Message lost on restore',
    CHK_FAIL_RECV_MIX: 'Message misorder on restore',
    CHK_FAIL_CONNECT: 'Connectivity broken on restore',
    CHK_FAIL_CONNECT2: 'Connectivity broken the hard way on restore',
    CHK_FAIL_KILLED: 'Test process died unexpectedly',
    CHK_FAIL_DUMP: 'Cannot dump',
    CHK_FAIL_RESTORE: 'Cannot restore',
}


def chk_real_state(st):
    # Before enything else -- check that we still have
    # all the sockets at hands
    for sk in st.sockets:
        if not sk.visible:
            continue

        # In theory we can have key-not-found exception here,
        # but this has nothing to do with sockets restore,
        # since it's just bytes in memory, so ... we assume
        # that we have object here and just check for it in
        # the fdtable
        rsk = st.real_sockets[sk.sk_id]
        try:
            s_st = os.fstat(rsk.fileno())
        except:
            print('FAIL: Socket %d lost' % sk.sk_id)
            return CHK_FAIL_SOCKET
        if not stat.S_ISSOCK(s_st.st_mode):
            print('FAIL: Not a socket %d at %d' % (sk.sk_id, rsk.fileno()))
            return CHK_FAIL_STAT

    # First -- check the listen states and names
    for sk in st.sockets:
        if not sk.visible:
            continue

        rsk = st.real_sockets[sk.sk_id]
        r_listen = rsk.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        if (sk.listen and r_listen == 0) or (not sk.listen and r_listen == 1):
            print("FAIL: Socket %d listen %d, expected %d" %
                  (sk.sk_id, r_listen, sk.listen and 1 or 0))
            return CHK_FAIL_LISTEN

        if sk.name:
            r_name = rsk.getsockname()
            w_name = sock.real_name_for(sk.name)
            if r_name != w_name:
                print('FAIL: Socket %d name mismatch [%s], want [%s]' %
                      (sk.sk_id, r_name, w_name))
                return CHK_FAIL_NAME

    # Second -- check (accept) pending connections
    for sk in st.sockets:
        if not sk.listen:
            continue

        rsk = st.real_sockets[sk.sk_id]
        set_nonblock(rsk)

        while sk.icons:
            # Do act_accept to change the state properly
            # and not write the code twice
            acc = act_accept(sk.sk_id)
            acc.act(st)
            try:
                acc.do(st)
            except:
                print('FAIL: Cannot accept pending connection for %d' %
                      sk.sk_id)
                return CHK_FAIL_ACCEPT

            print('  `- did %s' % acc.show())

    # Third -- check inqueues
    for sk in st.sockets:
        if not sk.inqueue:
            continue

        rsk = st.real_sockets[sk.sk_id]
        set_nonblock(rsk)

        while sk.inqueue:
            msg = sk.inqueue.pop(0)
            try:
                r_msg, m_from = rsk.recvfrom(128)
            except:
                print('FAIL: No message in queue for %d' % sk.sk_id)
                return CHK_FAIL_RECV_0

            w_msg = act_sendmsg.msgval(msg[1])
            if r_msg != w_msg:
                print('FAIL: Message misorder: %s want %s (from %d)' %
                      (r_msg, w_msg, msg[0]))
                return CHK_FAIL_RECV_MIX

            # TODO -- check sender
            print('  `- recvd %d.%d msg %s -> %d' %
                  (msg[0], msg[1], m_from, sk.sk_id))

    # Finally, after all sockets are visible and all inqueues are
    # drained -- check the sockets connectivity
    for sk in st.sockets:
        if not sk.peer:
            continue

        # Closed connection with one peer alive. Cannot check.
        if not sk.peer in st.real_sockets:
            continue

        rsk = st.real_sockets[sk.sk_id]
        psk = st.real_sockets[sk.peer]
        set_nonblock(psk)
        msgv = act_sendmsg.msgval(3 * sk.sk_id + 5 * sk.peer,
                                  'C')  # just random

        try:
            rsk.send(msgv)
            rmsg = psk.recv(128)
        except:
            print('FAIL: Connectivity %d -> %d lost' % (sk.sk_id, sk.peer))
            return CHK_FAIL_CONNECT

        # If sockets are not connected the recv above
        # would generate exception and the check would
        # fail. But just in case we've screwed the queues
        # the hard way -- also check for the message being
        # delivered for real
        if rmsg != msgv:
            print('FAIL: Connectivity %d -> %d not verified' %
                  (sk.sk_id, sk.peer))
            return CHK_FAIL_CONNECT2

        print('  `- checked %d -> %d with %s' % (sk.sk_id, sk.peer, msgv))

    return CHK_PASS


def chk_state(st, opts):
    print("Will check state")

    sigsk_name = "\0" + "CRSIGSKC"
    signal_sk = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    signal_sk.bind(sigsk_name)

    # FIXME Ideally call to criu should be performed by the run_state's
    # pid!=0 branch, but for simplicity we fork the kid which has the
    # same set of sockets we do, then dump it. Then restore and notify
    # via dgram socket to check its state. Current task still has all
    # the same sockets :) so we close them not to produce bind() name
    # conflicts on restore

    pid = os.fork()
    if pid == 0:
        msg = signal_sk.recv(64)
        ret = chk_real_state(st)
        sys.exit(ret)

    signal_sk.close()
    for rsk in st.real_sockets.values():
        rsk.close()

    print("`- dump")
    img_path = "sti_" + st.describe()
    try:
        os.mkdir(img_path)
        subprocess.check_call([
            criu_bin, "dump", "-t",
            "%d" % pid, "-D", img_path, "-v4", "-o", "dump.log", "-j"
        ])
    except:
        print("Dump failed")
        os.kill(pid, signal.SIGKILL)
        return CHK_FAIL_DUMP

    print("`- restore")
    try:
        os.waitpid(pid, 0)
        subprocess.check_call([
            criu_bin, "restore", "-D", img_path, "-v4", "-o", "rst.log", "-j",
            "-d", "-S"
        ])
    except:
        print("Restore failed")
        return CHK_FAIL_RESTORE

    print("`- check")
    signal_sk = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    try:
        signal_sk.sendto('check', sigsk_name)
    except:
        # Probably the peer has died before us or smth else went wrong
        os.kill(pid, signal.SIGKILL)

    wp, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        status = os.WEXITSTATUS(status)
        if status != CHK_PASS:
            print("`- exited with %d" % status)
            return status
    elif os.WIFSIGNALED(status):
        status = os.WTERMSIG(status)
        print("`- killed with %d" % status)
        return CHK_FAIL_KILLED
    else:
        return CHK_FAIL_UNKNOWN

    return CHK_PASS


def run_state(st, opts):
    print("Will run state")
    pid = os.fork()
    if pid != 0:
        wpid, status = os.wait()
        if os.WIFEXITED(status):
            status = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            status = CHK_FAIL_KILLED
        else:
            status = CHK_FAIL_UNKNOWN
        return status

    # Try the states in subprocess so that once
    # it exits the created sockets are removed
    for step in st.steps:
        step.do(st)

    if not opts.run:
        ret = chk_state(st, opts)
    else:
        ret = chk_real_state(st)

    sys.exit(ret)


def proceed(st, seen, failed, opts, depth=0):
    desc = st.describe()
    if not desc:
        pass
    elif not desc in seen:
        # When scanning the tree we run and try only states that
        # differ, but don't stop tree traversal on them. This is
        # because sometimes we can get into the already seen state
        # using less steps and it's better to proceed as we have
        # depth to move forward and generate more states.
        seen[desc] = len(st.steps)
        print('%s' % desc)
        for s in st.steps:
            print('\t%s' % s.show())

        if not opts.gen:
            ret = run_state(st, opts)
            if ret != CHK_PASS:
                failed.add((desc, ret))
                if not opts.keep:
                    return False
    else:
        # Don't even proceed with this state if we've already
        # seen one but get there with less steps
        seen_score = seen[desc]
        if len(st.steps) > seen_score:
            return True
        else:
            seen[desc] = len(st.steps)

    if depth >= opts.depth:
        return True

    actions = st.get_actions()
    for act in actions:
        nst = st.clone()
        act.act(nst)
        nst.steps.append(act)
        if not proceed(nst, seen, failed, opts, depth + 1):
            return False

    return True


p = argparse.ArgumentParser("CRIU test suite")
p.add_argument("--depth", help="Depth of generated tree", default='8')
p.add_argument("--sockets", help="Maximum number of sockets", default='1')
p.add_argument("--dgram", help="Use SOCK_DGRAM sockets", action='store_true')
p.add_argument("--stream", help="Use SOCK_STREAM sockets", action='store_true')
p.add_argument("--gen",
               help="Only generate and show states",
               action='store_true')
p.add_argument("--run",
               help="Run the states, but don't C/R",
               action='store_true')
p.add_argument("--keep", help="Don't stop on error", action='store_true')
opts = p.parse_args()
opts.depth = int(opts.depth)

# XXX: does it make any sense to mix two types in one go?
if opts.stream and opts.dgram:
    print('Choose only one type')
    sys.exit(1)

if opts.stream:
    sk_type = socket.SOCK_STREAM
elif opts.dgram:
    sk_type = socket.SOCK_DGRAM
else:
    print('Choose some type')
    sys.exit(1)

st = state(int(opts.sockets), sk_type)
seen = {}
failed = set()
proceed(st, seen, failed, opts)

if len(failed) == 0:
    print('PASS (%d states)' % len(seen))
else:
    print('FAIL %d/%d' % (len(failed), len(seen)))
    for f in failed:
        print("\t%-50s: %s" %
              (f[0], fail_desc.get(f[1], 'unknown reason %d' % f[1])))
