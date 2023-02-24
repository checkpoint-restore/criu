# This file contains methods to deal with criu images.
#
# According to http://criu.org/Images, criu images can be described
# with such IOW:
#
# IMAGE_FILE ::= MAGIC { ENTRY }
# ENTRY      ::= SIZE PAYLOAD [ EXTRA ]
# PAYLOAD    ::= "message encoded in ProtocolBuffer format"
# EXTRA      ::= "arbitrary blob, depends on the PAYLOAD contents"
#
# MAGIC      ::= "32 bit integer"
# SIZE       ::= "32 bit integer, equals the PAYLOAD length"
#
# Images v1.1 NOTE: MAGIC now consist of 2 32 bit integers, first one is
#    MAGIC_COMMON or MAGIC_SERVICE and the second one is same as MAGIC
#    in images V1.0. We don't keep "first" magic in json images.
#
# In order to convert images to human-readable format, we use dict(json).
# Using json not only allows us to easily read\write images, but also
# to use a great variety of tools out there to manipulate them.
# It also allows us to clearly describe criu images structure.
#
# Using dict(json) format, criu images can be described like:
#
# {
#    'magic' : 'FOO',
#    'entries' : [
#        entry,
#        ...
#    ]
# }
#
# Entry, in its turn, could be described as:
#
# {
#    pb_msg,
#    'extra' : extra_msg
# }
#
import io
import base64
import struct
import os
import array
import sys

from . import magic
from . import pb
from . import pb2dict

if "encodebytes" not in dir(base64):
    base64.encodebytes = base64.encodestring
    base64.decodebytes = base64.decodestring

#
# Predefined hardcoded constants
sizeof_u16 = 2
sizeof_u32 = 4
sizeof_u64 = 8


# A helper for rounding
def round_up(x, y):
    return (((x - 1) | (y - 1)) + 1)


class MagicException(Exception):
    def __init__(self, magic):
        self.magic = magic


def decode_base64_data(data):
    """A helper function to decode base64 data."""
    if (sys.version_info > (3, 0)):
        return base64.decodebytes(str.encode(data))
    else:
        return base64.decodebytes(data)


def write_base64_data(f, data):
    """A helper function to write base64 encoded data to a file."""
    if (sys.version_info > (3, 0)):
        f.write(base64.decodebytes(str.encode(data)))
    else:
        f.write(base64.decodebytes(data))


# Generic class to handle loading/dumping criu images entries from/to bin
# format to/from dict(json).
class entry_handler:
    """
    Generic class to handle loading/dumping criu images
    entries from/to bin format to/from dict(json).
    """

    def __init__(self, payload, extra_handler=None):
        """
        Sets payload class and extra handler class.
        """
        self.payload = payload
        self.extra_handler = extra_handler

    def load(self, f, pretty=False, no_payload=False):
        """
        Convert criu image entries from binary format to dict(json).
        Takes a file-like object and returns a list with entries in
        dict(json) format.
        """
        entries = []

        while True:
            entry = {}

            # Read payload
            pbuff = self.payload()
            buf = f.read(4)
            if len(buf) == 0:
                break
            size, = struct.unpack('i', buf)
            pbuff.ParseFromString(f.read(size))
            entry = pb2dict.pb2dict(pbuff, pretty)

            # Read extra
            if self.extra_handler:
                if no_payload:

                    def human_readable(num):
                        for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
                            if num < 1024.0:
                                if int(num) == num:
                                    return "%d%sB" % (num, unit)
                                else:
                                    return "%.1f%sB" % (num, unit)
                            num /= 1024.0
                        return "%.1fYB" % num

                    pl_size = self.extra_handler.skip(f, pbuff)
                    entry['extra'] = '... <%s>' % human_readable(pl_size)
                else:
                    entry['extra'] = self.extra_handler.load(f, pbuff)

            entries.append(entry)

        return entries

    def loads(self, s, pretty=False):
        """
        Same as load(), but takes a string as an argument.
        """
        f = io.BytesIO(s)
        return self.load(f, pretty)

    def dump(self, entries, f):
        """
        Convert criu image entries from dict(json) format to binary.
        Takes a list of entries and a file-like object to write entries
        in binary format to.
        """
        for entry in entries:
            extra = entry.pop('extra', None)

            # Write payload
            pbuff = self.payload()
            pb2dict.dict2pb(entry, pbuff)
            pb_str = pbuff.SerializeToString()
            size = len(pb_str)
            f.write(struct.pack('i', size))
            f.write(pb_str)

            # Write extra
            if self.extra_handler and extra:
                self.extra_handler.dump(extra, f, pbuff)

    def dumps(self, entries):
        """
        Same as dump(), but doesn't take file-like object and just
        returns a string.
        """
        f = io.BytesIO('')
        self.dump(entries, f)
        return f.read()

    def count(self, f):
        """
        Counts the number of top-level object in the image file
        """
        entries = 0

        while True:
            buf = f.read(4)
            if len(buf) == 0:
                break
            size, = struct.unpack('i', buf)
            f.seek(size, 1)
            entries += 1

        return entries


# Special handler for pagemap.img
class pagemap_handler:
    """
    Special entry handler for pagemap.img, which is unique in a way
    that it has a header of pagemap_head type followed by entries
    of pagemap_entry type.
    """

    def load(self, f, pretty=False, no_payload=False):
        entries = []

        pbuff = pb.pagemap_head()
        while True:
            buf = f.read(4)
            if len(buf) == 0:
                break
            size, = struct.unpack('i', buf)
            pbuff.ParseFromString(f.read(size))
            entries.append(pb2dict.pb2dict(pbuff, pretty))

            pbuff = pb.pagemap_entry()

        return entries

    def loads(self, s, pretty=False):
        f = io.BytesIO(s)
        return self.load(f, pretty)

    def dump(self, entries, f):
        pbuff = pb.pagemap_head()
        for item in entries:
            pb2dict.dict2pb(item, pbuff)
            pb_str = pbuff.SerializeToString()
            size = len(pb_str)
            f.write(struct.pack('i', size))
            f.write(pb_str)

            pbuff = pb.pagemap_entry()

    def dumps(self, entries):
        f = io.BytesIO('')
        self.dump(entries, f)
        return f.read()

    def count(self, f):
        return entry_handler(None).count(f) - 1


# Special handler for ghost-file.img
class ghost_file_handler:
    def load(self, f, pretty=False, no_payload=False):
        entries = []

        gf = pb.ghost_file_entry()
        buf = f.read(4)
        size, = struct.unpack('i', buf)
        gf.ParseFromString(f.read(size))
        g_entry = pb2dict.pb2dict(gf, pretty)

        if gf.chunks:
            entries.append(g_entry)
            while True:
                gc = pb.ghost_chunk_entry()
                buf = f.read(4)
                if len(buf) == 0:
                    break
                size, = struct.unpack('i', buf)
                gc.ParseFromString(f.read(size))
                entry = pb2dict.pb2dict(gc, pretty)
                if no_payload:
                    f.seek(gc.len, os.SEEK_CUR)
                else:
                    entry['extra'] = base64.encodebytes(f.read(gc.len)).decode('utf-8')
                entries.append(entry)
        else:
            if no_payload:
                f.seek(0, os.SEEK_END)
            else:
                g_entry['extra'] = base64.encodebytes(f.read()).decode('utf-8')
            entries.append(g_entry)

        return entries

    def loads(self, s, pretty=False):
        f = io.BytesIO(s)
        return self.load(f, pretty)

    def dump(self, entries, f):
        pbuff = pb.ghost_file_entry()
        item = entries.pop(0)
        pb2dict.dict2pb(item, pbuff)
        pb_str = pbuff.SerializeToString()
        size = len(pb_str)
        f.write(struct.pack('i', size))
        f.write(pb_str)

        if pbuff.chunks:
            for item in entries:
                pbuff = pb.ghost_chunk_entry()
                pb2dict.dict2pb(item, pbuff)
                pb_str = pbuff.SerializeToString()
                size = len(pb_str)
                f.write(struct.pack('i', size))
                f.write(pb_str)
                write_base64_data(f, item['extra'])
        else:
            write_base64_data(f, item['extra'])

    def dumps(self, entries):
        f = io.BytesIO('')
        self.dump(entries, f)
        return f.read()


# In following extra handlers we use base64 encoding
# to store binary data. Even though, the nature
# of base64 is that it increases the total size,
# it doesn't really matter, because our images
# do not store big amounts of binary data. They
# are negligible comparing to pages size.
class pipes_data_extra_handler:
    def load(self, f, pload):
        size = pload.bytes
        data = f.read(size)
        return base64.encodebytes(data).decode('utf-8')

    def dump(self, extra, f, pload):
        data = decode_base64_data(extra)
        f.write(data)

    def skip(self, f, pload):
        f.seek(pload.bytes, os.SEEK_CUR)
        return pload.bytes


class sk_queues_extra_handler:
    def load(self, f, pload):
        size = pload.length
        data = f.read(size)
        return base64.encodebytes(data).decode('utf-8')

    def dump(self, extra, f, _unused):
        data = decode_base64_data(extra)
        f.write(data)

    def skip(self, f, pload):
        f.seek(pload.length, os.SEEK_CUR)
        return pload.length


class tcp_stream_extra_handler:
    def load(self, f, pbuff):
        d = {}

        inq = f.read(pbuff.inq_len)
        outq = f.read(pbuff.outq_len)

        d['inq'] = base64.encodebytes(inq).decode('utf-8')
        d['outq'] = base64.encodebytes(outq).decode('utf-8')

        return d

    def dump(self, extra, f, _unused):
        inq = decode_base64_data(extra['inq'])
        outq = decode_base64_data(extra['outq'])

        f.write(inq)
        f.write(outq)

    def skip(self, f, pbuff):
        f.seek(0, os.SEEK_END)
        return pbuff.inq_len + pbuff.outq_len


class bpfmap_data_extra_handler:
    def load(self, f, pload):
        size = pload.keys_bytes + pload.values_bytes
        data = f.read(size)
        return base64.encodebytes(data).decode('utf-8')

    def dump(self, extra, f, pload):
        data = base64.decodebytes(extra)
        f.write(data)

    def skip(self, f, pload):
        f.seek(pload.bytes, os.SEEK_CUR)
        return pload.bytes


class ipc_sem_set_handler:
    def load(self, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = sizeof_u16 * entry['nsems']
        rounded = round_up(size, sizeof_u64)
        s = self._get_sem_array()
        s.frombytes(f.read(size))
        f.seek(rounded - size, 1)
        return s.tolist()

    def dump(self, extra, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = sizeof_u16 * entry['nsems']
        rounded = round_up(size, sizeof_u64)
        s = self._get_sem_array()
        s.fromlist(extra)
        if len(s) != entry['nsems']:
            raise Exception("Number of semaphores mismatch")
        f.write(s.tobytes())
        f.write(b'\0' * (rounded - size))

    def skip(self, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = sizeof_u16 * entry['nsems']
        f.seek(round_up(size, sizeof_u64), os.SEEK_CUR)
        return size

    def _get_sem_array(self):
        s = array.array('H')
        if s.itemsize != sizeof_u16:
            raise Exception("Array size mismatch")
        return s


class ipc_msg_queue_handler:
    def load(self, f, pbuff):
        messages, _ = self._read_messages(f, pbuff)
        return messages

    def dump(self, extra, f, pbuff):
        for i in range(0, len(extra), 2):
            msg = pb.ipc_msg()
            pb2dict.dict2pb(extra[i], msg)
            msg_str = msg.SerializeToString()
            size = len(msg_str)
            f.write(struct.pack('i', size))
            f.write(msg_str)
            rounded = round_up(msg.msize, sizeof_u64)
            data = decode_base64_data(extra[i + 1])
            f.write(data[:msg.msize])
            f.write(b'\0' * (rounded - msg.msize))

    def skip(self, f, pbuff):
        _, pl_len = self._read_messages(f, pbuff, skip_data=True)
        return pl_len

    def _read_messages(self, f, pbuff, skip_data=False):
        entry = pb2dict.pb2dict(pbuff)
        messages = []
        pl_len = 0
        for x in range(0, entry['qnum']):
            buf = f.read(4)
            if len(buf) == 0:
                break
            size, = struct.unpack('i', buf)
            msg = pb.ipc_msg()
            msg.ParseFromString(f.read(size))
            rounded = round_up(msg.msize, sizeof_u64)
            pl_len += size + msg.msize

            if skip_data:
                f.seek(rounded, os.SEEK_CUR)
            else:
                data = f.read(msg.msize)
                f.seek(rounded - msg.msize, 1)
                messages.append(pb2dict.pb2dict(msg))
                messages.append(base64.encodebytes(data).decode('utf-8'))

        return messages, pl_len


class ipc_shm_handler:
    def load(self, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = entry['size']
        data = f.read(size)
        rounded = round_up(size, sizeof_u32)
        f.seek(rounded - size, 1)
        return base64.encodebytes(data).decode('utf-8')

    def dump(self, extra, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = entry['size']
        data = base64.decodebytes(extra)
        rounded = round_up(size, sizeof_u32)
        f.write(data[:size])
        f.write(b'\0' * (rounded - size))

    def skip(self, f, pbuff):
        entry = pb2dict.pb2dict(pbuff)
        size = entry['size']
        rounded = round_up(size, sizeof_u32)
        f.seek(rounded, os.SEEK_CUR)
        return size


handlers = {
    'INVENTORY': entry_handler(pb.inventory_entry),
    'CORE': entry_handler(pb.core_entry),
    'IDS': entry_handler(pb.task_kobj_ids_entry),
    'CREDS': entry_handler(pb.creds_entry),
    'UTSNS': entry_handler(pb.utsns_entry),
    'TIMENS': entry_handler(pb.timens_entry),
    'PIDNS': entry_handler(pb.pidns_entry),
    'IPC_VAR': entry_handler(pb.ipc_var_entry),
    'FS': entry_handler(pb.fs_entry),
    'GHOST_FILE': ghost_file_handler(),
    'MM': entry_handler(pb.mm_entry),
    'CGROUP': entry_handler(pb.cgroup_entry),
    'TCP_STREAM': entry_handler(pb.tcp_stream_entry,
                                tcp_stream_extra_handler()),
    'STATS': entry_handler(pb.stats_entry),
    'PAGEMAP': pagemap_handler(),  # Special one
    'PSTREE': entry_handler(pb.pstree_entry),
    'REG_FILES': entry_handler(pb.reg_file_entry),
    'NS_FILES': entry_handler(pb.ns_file_entry),
    'EVENTFD_FILE': entry_handler(pb.eventfd_file_entry),
    'EVENTPOLL_FILE': entry_handler(pb.eventpoll_file_entry),
    'EVENTPOLL_TFD': entry_handler(pb.eventpoll_tfd_entry),
    'SIGNALFD': entry_handler(pb.signalfd_entry),
    'TIMERFD': entry_handler(pb.timerfd_entry),
    'INOTIFY_FILE': entry_handler(pb.inotify_file_entry),
    'INOTIFY_WD': entry_handler(pb.inotify_wd_entry),
    'FANOTIFY_FILE': entry_handler(pb.fanotify_file_entry),
    'FANOTIFY_MARK': entry_handler(pb.fanotify_mark_entry),
    'VMAS': entry_handler(pb.vma_entry),
    'PIPES': entry_handler(pb.pipe_entry),
    'FIFO': entry_handler(pb.fifo_entry),
    'SIGACT': entry_handler(pb.sa_entry),
    'NETLINK_SK': entry_handler(pb.netlink_sk_entry),
    'REMAP_FPATH': entry_handler(pb.remap_file_path_entry),
    'MNTS': entry_handler(pb.mnt_entry),
    'TTY_FILES': entry_handler(pb.tty_file_entry),
    'TTY_INFO': entry_handler(pb.tty_info_entry),
    'TTY_DATA': entry_handler(pb.tty_data_entry),
    'RLIMIT': entry_handler(pb.rlimit_entry),
    'TUNFILE': entry_handler(pb.tunfile_entry),
    'EXT_FILES': entry_handler(pb.ext_file_entry),
    'IRMAP_CACHE': entry_handler(pb.irmap_cache_entry),
    'FILE_LOCKS': entry_handler(pb.file_lock_entry),
    'FDINFO': entry_handler(pb.fdinfo_entry),
    'UNIXSK': entry_handler(pb.unix_sk_entry),
    'INETSK': entry_handler(pb.inet_sk_entry),
    'PACKETSK': entry_handler(pb.packet_sock_entry),
    'ITIMERS': entry_handler(pb.itimer_entry),
    'POSIX_TIMERS': entry_handler(pb.posix_timer_entry),
    'NETDEV': entry_handler(pb.net_device_entry),
    'PIPES_DATA': entry_handler(pb.pipe_data_entry,
                                pipes_data_extra_handler()),
    'FIFO_DATA': entry_handler(pb.pipe_data_entry, pipes_data_extra_handler()),
    'SK_QUEUES': entry_handler(pb.sk_packet_entry, sk_queues_extra_handler()),
    'IPCNS_SHM': entry_handler(pb.ipc_shm_entry, ipc_shm_handler()),
    'IPCNS_SEM': entry_handler(pb.ipc_sem_entry, ipc_sem_set_handler()),
    'IPCNS_MSG': entry_handler(pb.ipc_msg_entry, ipc_msg_queue_handler()),
    'NETNS': entry_handler(pb.netns_entry),
    'USERNS': entry_handler(pb.userns_entry),
    'SECCOMP': entry_handler(pb.seccomp_entry),
    'AUTOFS': entry_handler(pb.autofs_entry),
    'FILES': entry_handler(pb.file_entry),
    'CPUINFO': entry_handler(pb.cpuinfo_entry),
    'MEMFD_FILE': entry_handler(pb.memfd_file_entry),
    'MEMFD_INODE': entry_handler(pb.memfd_inode_entry),
    'BPFMAP_FILE': entry_handler(pb.bpfmap_file_entry),
    'BPFMAP_DATA': entry_handler(pb.bpfmap_data_entry,
                                 bpfmap_data_extra_handler()),
    'APPARMOR': entry_handler(pb.apparmor_entry),
}


def __rhandler(f):
    # Images v1.1 NOTE: First read "first" magic.
    img_magic, = struct.unpack('i', f.read(4))
    if img_magic in (magic.by_name['IMG_COMMON'],
                     magic.by_name['IMG_SERVICE']):
        img_magic, = struct.unpack('i', f.read(4))

    try:
        m = magic.by_val[img_magic]
    except Exception:
        raise MagicException(img_magic)

    try:
        handler = handlers[m]
    except Exception:
        raise Exception("No handler found for image with magic " + m)

    return m, handler


def load(f, pretty=False, no_payload=False):
    """
    Convert criu image from binary format to dict(json).
    Takes a file-like object to read criu image from.
    Returns criu image in dict(json) format.
    """
    image = {}

    m, handler = __rhandler(f)

    image['magic'] = m
    image['entries'] = handler.load(f, pretty, no_payload)

    return image


def info(f):
    res = {}

    m, handler = __rhandler(f)

    res['magic'] = m
    res['count'] = handler.count(f)

    return res


def loads(s, pretty=False):
    """
    Same as load(), but takes a string.
    """
    f = io.BytesIO(s)
    return load(f, pretty)


def dump(img, f):
    """
    Convert criu image from dict(json) format to binary.
    Takes an image in dict(json) format and file-like
    object to write to.
    """
    m = img['magic']
    magic_val = magic.by_name[img['magic']]

    # Images v1.1 NOTE: use "second" magic to identify what "first"
    # should be written.
    if m != 'INVENTORY':
        if m in ('STATS', 'IRMAP_CACHE'):
            f.write(struct.pack('i', magic.by_name['IMG_SERVICE']))
        else:
            f.write(struct.pack('i', magic.by_name['IMG_COMMON']))

    f.write(struct.pack('i', magic_val))

    try:
        handler = handlers[m]
    except Exception:
        raise Exception("No handler found for image with such magic")

    handler.dump(img['entries'], f)


def dumps(img):
    """
    Same as dump(), but takes only an image and returns
    a string.
    """
    f = io.BytesIO(b'')
    dump(img, f)
    return f.getvalue()
