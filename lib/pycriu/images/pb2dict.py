import base64
import collections
import os
import quopri
import socket
from ipaddress import IPv4Address, IPv6Address, ip_address

from google.protobuf.descriptor import FieldDescriptor as FD

import opts_pb2

if "encodebytes" not in dir(base64):
    base64.encodebytes = base64.encodestring
    base64.decodebytes = base64.decodestring

# pb2dict and dict2pb are methods to convert pb to/from dict.
# Inspired by:
#   protobuf-to-dict - https://github.com/benhodgson/protobuf-to-dict
#   protobuf-json    - https://code.google.com/p/protobuf-json/
#   protobuf source  - https://code.google.com/p/protobuf/
# Both protobuf-to-dict/json do not fit here because of several reasons,
# here are some of them:
#   - both have a common bug in treating optional field with empty
#     repeated inside.
#   - protobuf-to-json is not available in pip or in any other python
#     repo, so it is hard to distribute and we can't rely on it.
#   - both do not treat enums in a way we would like to. They convert
#     protobuf enum to int, but we need a string here, because it is
#     much more informative. BTW, protobuf text_format converts pb
#     enums to string value too. (i.e. "march : x86_64" is better then
#     "march : 1").

_basic_cast = {
    FD.TYPE_FIXED64: int,
    FD.TYPE_FIXED32: int,
    FD.TYPE_SFIXED64: int,
    FD.TYPE_SFIXED32: int,
    FD.TYPE_INT64: int,
    FD.TYPE_UINT64: int,
    FD.TYPE_SINT64: int,
    FD.TYPE_INT32: int,
    FD.TYPE_UINT32: int,
    FD.TYPE_SINT32: int,
    FD.TYPE_BOOL: bool,
    FD.TYPE_STRING: str
}


def _marked_as_hex(field):
    return field.GetOptions().Extensions[opts_pb2.criu].hex


def _marked_as_ip(field):
    return field.GetOptions().Extensions[opts_pb2.criu].ipadd


def _marked_as_flags(field):
    return field.GetOptions().Extensions[opts_pb2.criu].flags


def _marked_as_dev(field):
    return field.GetOptions().Extensions[opts_pb2.criu].dev


def _marked_as_odev(field):
    return field.GetOptions().Extensions[opts_pb2.criu].odev


def _marked_as_dict(field):
    return field.GetOptions().Extensions[opts_pb2.criu].dict


def _custom_conv(field):
    return field.GetOptions().Extensions[opts_pb2.criu].conv


mmap_prot_map = [
    ('PROT_READ', 0x1),
    ('PROT_WRITE', 0x2),
    ('PROT_EXEC', 0x4),
]

mmap_flags_map = [
    ('MAP_SHARED', 0x1),
    ('MAP_PRIVATE', 0x2),
    ('MAP_DROPPABLE', 0x08),
    ('MAP_ANON', 0x20),
    ('MAP_GROWSDOWN', 0x0100),
]

mmap_status_map = [
    ('VMA_AREA_NONE', 0 << 0),
    ('VMA_AREA_REGULAR', 1 << 0),
    ('VMA_AREA_STACK', 1 << 1),
    ('VMA_AREA_VSYSCALL', 1 << 2),
    ('VMA_AREA_VDSO', 1 << 3),
    ('VMA_AREA_HEAP', 1 << 5),
    ('VMA_FILE_PRIVATE', 1 << 6),
    ('VMA_FILE_SHARED', 1 << 7),
    ('VMA_ANON_SHARED', 1 << 8),
    ('VMA_ANON_PRIVATE', 1 << 9),
    ('VMA_AREA_SYSVIPC', 1 << 10),
    ('VMA_AREA_SOCKET', 1 << 11),
    ('VMA_AREA_VVAR', 1 << 12),
    ('VMA_AREA_AIORING', 1 << 13),
    ('VMA_AREA_MEMFD', 1 << 14),
    ('VMA_AREA_SHSTK', 1 << 15),
    ('VMA_AREA_UPROBES', 1 << 17),
    ('VMA_UNSUPP', 1 << 31),
]

rfile_flags_map = [
    ('O_WRONLY', 0o00000001),
    ('O_RDWR', 0o00000002),
    ('O_CREAT', 0o00000100),
    ('O_EXCL', 0o00000200),
    ('O_NOCTTY', 0o00000400),
    ('O_TRUNC', 0o00001000),
    ('O_APPEND', 0o00002000),
    ('O_NONBLOCK', 0o00004000),
    ('O_DSYNC', 0o00010000),
    ('FASYNC', 0o00020000),
    ('O_DIRECT', 0o00040000),
    ('O_LARGEFILE', 0o00100000),
    ('O_DIRECTORY', 0o00200000),
    ('O_NOFOLLOW', 0o00400000),
    ('O_NOATIME', 0o01000000),
    ('O_CLOEXEC', 0o02000000),
]

seals_flags_map = [
    ('F_SEAL_SEAL', 0x0001),
    ('F_SEAL_SHRINK', 0x0002),
    ('F_SEAL_GROW', 0x0004),
    ('F_SEAL_WRITE', 0x0008),
    ('F_SEAL_FUTURE_WRITE', 0x0010),
]

pmap_flags_map = [
    ('PE_PARENT', 1 << 0),
    ('PE_LAZY', 1 << 1),
    ('PE_PRESENT', 1 << 2),
]

flags_maps = {
    'mmap.prot': mmap_prot_map,
    'mmap.flags': mmap_flags_map,
    'mmap.status': mmap_status_map,
    'rfile.flags': rfile_flags_map,
    'pmap.flags': pmap_flags_map,
    'seals.flags': seals_flags_map,
}

gen_maps = {
    'task_state': {
        1: 'Alive',
        3: 'Zombie',
        6: 'Stopped'
    },
}

sk_maps = {
    'family': {
        1: 'UNIX',
        2: 'INET',
        10: 'INET6',
        16: 'NETLINK',
        17: 'PACKET'
    },
    'type': {
        1: 'STREAM',
        2: 'DGRAM',
        3: 'RAW',
        5: 'SEQPACKET',
        10: 'PACKET'
    },
    'state': {
        1: 'ESTABLISHED',
        2: 'SYN_SENT',
        3: 'SYN_RECV',
        4: 'FIN_WAIT1',
        5: 'FIN_WAIT2',
        6: 'TIME_WAIT',
        7: 'CLOSE',
        8: 'CLOSE_WAIT',
        9: 'LAST_ACK',
        10: 'LISTEN'
    },
    'proto': {
        0: 'IP',
        6: 'TCP',
        17: 'UDP',
        136: 'UDPLITE'
    },
}

gen_rmaps = {
    k: {v2: k2
        for k2, v2 in list(v.items())}
    for k, v in list(gen_maps.items())
}
sk_rmaps = {
    k: {v2: k2
        for k2, v2 in list(v.items())}
    for k, v in list(sk_maps.items())
}

dict_maps = {
    'gen': (gen_maps, gen_rmaps),
    'sk': (sk_maps, sk_rmaps),
}


def map_flags(value, flags_map):
    bs = [x[0] for x in [x for x in flags_map if value & x[1]]]
    value &= ~sum([x[1] for x in flags_map])
    if value:
        bs.append("0x%x" % value)
    return " | ".join(bs)


def unmap_flags(value, flags_map):
    if value == '':
        return 0

    bd = dict(flags_map)
    return sum([
        int(str(bd.get(x, x)), 0)
        for x in [x.strip() for x in value.split('|')]
    ])


kern_minorbits = 20  # This is how kernel encodes dev_t in new format


def decode_dev(field, value):
    if _marked_as_odev(field):
        return "%d:%d" % (os.major(value), os.minor(value))
    else:
        return "%d:%d" % (value >> kern_minorbits,
                          value & ((1 << kern_minorbits) - 1))


def encode_dev(field, value):
    dev = [int(x) for x in value.split(':')]
    if _marked_as_odev(field):
        return os.makedev(dev[0], dev[1])
    else:
        return dev[0] << kern_minorbits | dev[1]


def encode_base64(value):
    return base64.encodebytes(value).decode()


def decode_base64(value):
    return base64.decodebytes(str.encode(value))


def encode_unix(value):
    return quopri.encodestring(value)


def decode_unix(value):
    return quopri.decodestring(value)


encode = {'unix_name': encode_unix}
decode = {'unix_name': decode_unix}


def get_bytes_enc(field):
    c = _custom_conv(field)
    if c:
        return encode[c]
    else:
        return encode_base64


def get_bytes_dec(field):
    c = _custom_conv(field)
    if c:
        return decode[c]
    else:
        return decode_base64


def is_string(value):
    # Python 3 compatibility
    if "basestring" in __builtins__:
        string_types = basestring  # noqa: F821
    else:
        string_types = (str, bytes)
    return isinstance(value, string_types)


def _pb2dict_cast(field, value, pretty=False, is_hex=False):
    if not is_hex:
        is_hex = _marked_as_hex(field)

    if field.type == FD.TYPE_MESSAGE:
        return pb2dict(value, pretty, is_hex)
    elif field.type == FD.TYPE_BYTES:
        return get_bytes_enc(field)(value)
    elif field.type == FD.TYPE_ENUM:
        return field.enum_type.values_by_number.get(value, None).name
    elif field.type in _basic_cast:
        cast = _basic_cast[field.type]
        if pretty and cast is int:
            if is_hex:
                # Fields that have (criu).hex = true option set
                # should be stored in hex string format.
                return "0x%x" % value

            if _marked_as_dev(field):
                return decode_dev(field, value)

            flags = _marked_as_flags(field)
            if flags:
                try:
                    flags_map = flags_maps[flags]
                except Exception:
                    return "0x%x" % value  # flags are better seen as hex anyway
                else:
                    return map_flags(value, flags_map)

            dct = _marked_as_dict(field)
            if dct:
                return dict_maps[dct][0][field.name].get(value, cast(value))

        return cast(value)
    else:
        raise Exception("Field(%s) has unsupported type %d" %
                        (field.name, field.type))


def pb2dict(pb, pretty=False, is_hex=False):
    """
    Convert protobuf msg to dictionary.
    Takes a protobuf message and returns a dict.
    """
    d = collections.OrderedDict() if pretty else {}
    for field, value in pb.ListFields():
        if field.label == FD.LABEL_REPEATED:
            d_val = []
            if pretty and _marked_as_ip(field):
                if len(value) == 1:
                    v = socket.ntohl(value[0])
                    addr = IPv4Address(v)
                else:
                    v = 0 + (socket.ntohl(value[0]) << (32 * 3)) + \
                            (socket.ntohl(value[1]) << (32 * 2)) + \
                            (socket.ntohl(value[2]) << (32 * 1)) + \
                            (socket.ntohl(value[3]))
                    addr = IPv6Address(v)

                d_val.append(addr.compressed)
            else:
                for v in value:
                    d_val.append(_pb2dict_cast(field, v, pretty, is_hex))
        else:
            d_val = _pb2dict_cast(field, value, pretty, is_hex)

        try:
            d[field.name] = d_val.decode()
        except (UnicodeDecodeError, AttributeError):
            d[field.name] = d_val
    return d


def _dict2pb_cast(field, value):
    # Not considering TYPE_MESSAGE here, as repeated
    # and non-repeated messages need special treatment
    # in this case, and are handled separately.
    if field.type == FD.TYPE_BYTES:
        return get_bytes_dec(field)(value)
    elif field.type == FD.TYPE_ENUM:
        return field.enum_type.values_by_name.get(value, None).number
    elif field.type in _basic_cast:
        cast = _basic_cast[field.type]
        if cast is int and is_string(value):
            if _marked_as_dev(field):
                return encode_dev(field, value)

            flags = _marked_as_flags(field)
            if flags:
                try:
                    flags_map = flags_maps[flags]
                except Exception:
                    pass  # Try to use plain string cast
                else:
                    return unmap_flags(value, flags_map)

            dct = _marked_as_dict(field)
            if dct:
                ret = dict_maps[dct][1][field.name].get(value, None)
                if ret is None:
                    ret = cast(value, 0)
                return ret

            # Some int or long fields might be stored as hex
            # strings. See _pb2dict_cast.
            return cast(value, 0)
        else:
            return cast(value)
    else:
        raise Exception("Field(%s) has unsupported type %d" %
                        (field.name, field.type))


def dict2pb(d, pb):
    """
    Convert dictionary to protobuf msg.
    Takes dict and protobuf message to be merged into.
    """
    for field in pb.DESCRIPTOR.fields:
        if field.name not in d:
            continue
        value = d[field.name]
        if field.label == FD.LABEL_REPEATED:
            pb_val = getattr(pb, field.name, None)
            if is_string(value[0]) and _marked_as_ip(field):
                val = ip_address(value[0])
                if val.version == 4:
                    pb_val.append(socket.htonl(int(val)))
                elif val.version == 6:
                    ival = int(val)
                    pb_val.append(socket.htonl((ival >> (32 * 3)) & 0xFFFFFFFF))
                    pb_val.append(socket.htonl((ival >> (32 * 2)) & 0xFFFFFFFF))
                    pb_val.append(socket.htonl((ival >> (32 * 1)) & 0xFFFFFFFF))
                    pb_val.append(socket.htonl((ival >> (32 * 0)) & 0xFFFFFFFF))
                else:
                    raise Exception("Unknown IP address version %d" %
                                    val.version)
                continue

            for v in value:
                if field.type == FD.TYPE_MESSAGE:
                    dict2pb(v, pb_val.add())
                else:
                    pb_val.append(_dict2pb_cast(field, v))
        else:
            if field.type == FD.TYPE_MESSAGE:
                # SetInParent method acts just like has_* = true in C,
                # and helps to properly treat cases when we have optional
                # field with empty repeated inside.
                getattr(pb, field.name).SetInParent()

                dict2pb(value, getattr(pb, field.name, None))
            else:
                setattr(pb, field.name, _dict2pb_cast(field, value))
    return pb
