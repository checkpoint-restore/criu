#!/usr/bin/env python3
import argparse
import sys
import json
import os
from contextlib import contextmanager

import pycriu
from . import __version__


@contextmanager
def inf(opts):
    if opts['in']:
        f = open(opts['in'], 'rb')
        try:
            yield f
        finally:
            f.close()
    else:
        if sys.stdin.isatty():
            # If we are reading from a terminal (not a pipe) we want text input and not binary
            yield sys.stdin
        else:
            yield sys.stdin.buffer


@contextmanager
def outf(opts, decode):
    # Decode means from protobuf to JSON.
    # Use text when writing to JSON else use binaray mode
    if opts['out']:
        mode = 'wb+'
        if decode:
            mode = 'w+'
        f = open(opts['out'], mode)
        try:
            yield f
        finally:
            f.close()
    else:
        if decode:
            yield sys.stdout
        else:
            yield sys.stdout.buffer


@contextmanager
def dinf(opts, name):
    f = open(os.path.join(opts['dir'], name), mode='rb')
    try:
        yield f
    finally:
        f.close()


def decode(opts):
    indent = None

    try:
        with inf(opts) as i:
            img = pycriu.images.load(i, opts['pretty'], opts['nopl'])
    except pycriu.images.MagicException as exc:
        print("Unknown magic %#x.\n"
              "Maybe you are feeding me an image with "
              "raw data(i.e. pages.img)?" % exc.magic, file=sys.stderr)
        sys.exit(1)

    if opts['pretty']:
        indent = 4

    with outf(opts, True) as f:
        json.dump(img, f, indent=indent)
        if f == sys.stdout:
            f.write("\n")


def encode(opts):
    try:
        with inf(opts) as i:
            img = json.load(i)
    except UnicodeDecodeError:
        print("Cannot read JSON.\n"
              "Maybe you are feeding me an image with protobuf data? "
              "Encode expects JSON input.", file=sys.stderr)
        sys.exit(1)
    with outf(opts, False) as o:
        pycriu.images.dump(img, o)


def info(opts):
    with inf(opts) as i:
        infs = pycriu.images.info(i)
    json.dump(infs, sys.stdout, indent=4)
    print()


def get_task_id(p, val):
    return p[val] if val in p else p['ns_' + val][0]


#
# Explorers
#


class ps_item:
    def __init__(self, p, core):
        self.pid = get_task_id(p, 'pid')
        self.ppid = p['ppid']
        self.p = p
        self.core = core
        self.kids = []


def show_ps(p, opts, depth=0):
    print("%7d%7d%7d   %s%s" %
          (p.pid, get_task_id(p.p, 'pgid'), get_task_id(p.p, 'sid'), ' ' *
           (4 * depth), p.core['tc']['comm']))
    for kid in p.kids:
        show_ps(kid, opts, depth + 1)


def explore_ps(opts):
    pss = {}
    with dinf(opts, 'pstree.img') as f:
        ps_img = pycriu.images.load(f)
    for p in ps_img['entries']:
        with dinf(opts, 'core-%d.img' % get_task_id(p, 'pid')) as f:
            core = pycriu.images.load(f)
        ps = ps_item(p, core['entries'][0])
        pss[ps.pid] = ps

    # Build tree
    psr = None
    for pid in pss:
        p = pss[pid]
        if p.ppid == 0:
            psr = p
            continue

        pp = pss[p.ppid]
        pp.kids.append(p)

    print("%7s%7s%7s   %s" % ('PID', 'PGID', 'SID', 'COMM'))
    show_ps(psr, opts)


files_img = None


def ftype_find_in_files(opts, ft, fid):
    global files_img

    if files_img is None:
        try:
            with dinf(opts, "files.img") as f:
                files_img = pycriu.images.load(f)['entries']
        except Exception:
            files_img = []

    if len(files_img) == 0:
        return None

    for f in files_img:
        if f['id'] == fid:
            return f

    return None


def ftype_find_in_image(opts, ft, fid, img):
    f = ftype_find_in_files(opts, ft, fid)
    if f:
        if ft['field'] in f:
            return f[ft['field']]
        else:
            return None

    if ft['img'] is None:
        with dinf(opts, img) as f:
            ft['img'] = pycriu.images.load(f)['entries']
    for f in ft['img']:
        if f['id'] == fid:
            return f
    return None


def ftype_reg(opts, ft, fid):
    rf = ftype_find_in_image(opts, ft, fid, 'reg-files.img')
    return rf and rf['name'] or 'unknown path'


def ftype_pipe(opts, ft, fid):
    p = ftype_find_in_image(opts, ft, fid, 'pipes.img')
    return p and 'pipe[%d]' % p['pipe_id'] or 'pipe[?]'


def ftype_unix(opts, ft, fid):
    ux = ftype_find_in_image(opts, ft, fid, 'unixsk.img')
    if not ux:
        return 'unix[?]'

    n = ux['name'] and ' %s' % ux['name'] or ''
    return 'unix[%d (%d)%s]' % (ux['ino'], ux['peer'], n)


file_types = {
    'REG': {
        'get': ftype_reg,
        'img': None,
        'field': 'reg'
    },
    'PIPE': {
        'get': ftype_pipe,
        'img': None,
        'field': 'pipe'
    },
    'UNIXSK': {
        'get': ftype_unix,
        'img': None,
        'field': 'usk'
    },
}


def ftype_gen(opts, ft, fid):
    return '%s.%d' % (ft['typ'], fid)


files_cache = {}


def get_file_str(opts, fd):
    key = (fd['type'], fd['id'])
    f = files_cache.get(key, None)
    if not f:
        ft = file_types.get(fd['type'], {'get': ftype_gen, 'typ': fd['type']})
        f = ft['get'](opts, ft, fd['id'])
        files_cache[key] = f

    return f


def explore_fds(opts):
    with dinf(opts, 'pstree.img') as f:
        ps_img = pycriu.images.load(f)
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        with dinf(opts, 'ids-%s.img' % pid) as f:
            idi = pycriu.images.load(f)
        fdt = idi['entries'][0]['files_id']
        with dinf(opts, 'fdinfo-%d.img' % fdt) as f:
            fdi = pycriu.images.load(f)

        print("%d" % pid)
        for fd in fdi['entries']:
            print("\t%7d: %s" % (fd['fd'], get_file_str(opts, fd)))

        with dinf(opts, 'fs-%d.img' % pid) as f:
            fdi = pycriu.images.load(f)['entries'][0]
        print("\t%7s: %s" %
              ('cwd', get_file_str(opts, {
                  'type': 'REG',
                  'id': fdi['cwd_id']
              })))
        print("\t%7s: %s" %
              ('root', get_file_str(opts, {
                  'type': 'REG',
                  'id': fdi['root_id']
              })))


class vma_id:
    def __init__(self):
        self.__ids = {}
        self.__last = 1

    def get(self, iid):
        ret = self.__ids.get(iid, None)
        if not ret:
            ret = self.__last
            self.__last += 1
            self.__ids[iid] = ret

        return ret


def explore_mems(opts):
    with dinf(opts, 'pstree.img') as f:
        ps_img = pycriu.images.load(f)
    vids = vma_id()
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        with dinf(opts, 'mm-%d.img' % pid) as f:
            mmi = pycriu.images.load(f)['entries'][0]

        print("%d" % pid)
        print("\t%-36s    %s" % ('exe',
                                 get_file_str(opts, {
                                     'type': 'REG',
                                     'id': mmi['exe_file_id']
                                 })))

        for vma in mmi['vmas']:
            st = vma['status']
            if st & (1 << 10):
                fn = ' ' + 'ips[%lx]' % vids.get(vma['shmid'])
            elif st & (1 << 8):
                fn = ' ' + 'shmem[%lx]' % vids.get(vma['shmid'])
            elif st & (1 << 11):
                fn = ' ' + 'packet[%lx]' % vids.get(vma['shmid'])
            elif st & ((1 << 6) | (1 << 7)):
                fn = ' ' + get_file_str(opts, {
                    'type': 'REG',
                    'id': vma['shmid']
                })
                if vma['pgoff']:
                    fn += ' + %#lx' % vma['pgoff']
                if st & (1 << 7):
                    fn += ' (s)'
            elif st & (1 << 1):
                fn = ' [stack]'
            elif st & (1 << 2):
                fn = ' [vsyscall]'
            elif st & (1 << 3):
                fn = ' [vdso]'
            elif vma['flags'] & 0x0100:  # growsdown
                fn = ' [stack?]'
            else:
                fn = ''

            if not st & (1 << 0):
                fn += ' *'

            prot = vma['prot'] & 0x1 and 'r' or '-'
            prot += vma['prot'] & 0x2 and 'w' or '-'
            prot += vma['prot'] & 0x4 and 'x' or '-'

            astr = '%08lx-%08lx' % (vma['start'], vma['end'])
            print("\t%-36s%s%s" % (astr, prot, fn))


def explore_rss(opts):
    with dinf(opts, 'pstree.img') as f:
        ps_img = pycriu.images.load(f)
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        with dinf(opts, 'mm-%d.img' % pid) as f:
            vmas = pycriu.images.load(f)['entries'][0]['vmas']
        with dinf(opts, 'pagemap-%d.img' % pid) as f:
            pms = pycriu.images.load(f)['entries']

        print("%d" % pid)
        vmi = 0
        pvmi = -1
        for pm in pms[1:]:
            pstr = '\t%lx / %-8d' % (pm['vaddr'], pm['nr_pages'])
            while vmi < len(vmas) and vmas[vmi]['end'] <= pm['vaddr']:
                vmi += 1

            pme = pm['vaddr'] + (pm['nr_pages'] << 12)
            vstr = ''
            while vmi < len(vmas) and vmas[vmi]['start'] < pme:
                vma = vmas[vmi]
                if vmi == pvmi:
                    vstr += ' ~'
                else:
                    vstr += ' %08lx / %-8d' % (
                        vma['start'], (vma['end'] - vma['start']) >> 12)
                    if vma['status'] & ((1 << 6) | (1 << 7)):
                        vstr += ' ' + get_file_str(opts, {
                            'type': 'REG',
                            'id': vma['shmid']
                        })
                    pvmi = vmi
                vstr += '\n\t%23s' % ''
                vmi += 1

            vmi -= 1

            print('%-24s%s' % (pstr, vstr))


explorers = {
    'ps': explore_ps,
    'fds': explore_fds,
    'mems': explore_mems,
    'rss': explore_rss
}


def explore(opts):
    explorers[opts['what']](opts)


def main():
    desc = 'CRiu Image Tool'
    parser = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version=__version__)

    subparsers = parser.add_subparsers(
        help='Use crit CMD --help for command-specific help')

    # Decode
    decode_parser = subparsers.add_parser(
        'decode', help='convert criu image from binary type to json')
    decode_parser.add_argument(
        '--pretty',
        help='Multiline with indents and some numerical fields in field-specific format',
        action='store_true')
    decode_parser.add_argument(
        '-i',
        '--in',
        help='criu image in binary format to be decoded (stdin by default)')
    decode_parser.add_argument(
        '-o',
        '--out',
        help='where to put criu image in json format (stdout by default)')
    decode_parser.set_defaults(func=decode, nopl=False)

    # Encode
    encode_parser = subparsers.add_parser(
        'encode', help='convert criu image from json type to binary')
    encode_parser.add_argument(
        '-i',
        '--in',
        help='criu image in json format to be encoded (stdin by default)')
    encode_parser.add_argument(
        '-o',
        '--out',
        help='where to put criu image in binary format (stdout by default)')
    encode_parser.set_defaults(func=encode)

    # Info
    info_parser = subparsers.add_parser('info', help='show info about image')
    info_parser.add_argument("in")
    info_parser.set_defaults(func=info)

    # Explore
    x_parser = subparsers.add_parser('x', help='explore image dir')
    x_parser.add_argument('dir')
    x_parser.add_argument('what', choices=['ps', 'fds', 'mems', 'rss'])
    x_parser.set_defaults(func=explore)

    # Show
    show_parser = subparsers.add_parser(
        'show', help="convert criu image from binary to human-readable json")
    show_parser.add_argument("in")
    show_parser.add_argument('--nopl',
                             help='do not show entry payload (if exists)',
                             action='store_true')
    show_parser.set_defaults(func=decode, pretty=True, out=None)

    opts = vars(parser.parse_args())

    if not opts:
        sys.stderr.write(parser.format_usage())
        sys.stderr.write("crit: error: too few arguments\n")
        sys.exit(1)

    opts["func"](opts)


if __name__ == '__main__':
    main()
