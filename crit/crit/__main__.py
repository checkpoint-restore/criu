#!/usr/bin/env python3
import argparse
import bisect
import errno
import json
import os
import signal
import stat
import sys
import tempfile
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
                        vma['start'],
                        (vma['end'] - vma['start']) >> 12)
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


PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
if PAGE_SIZE <= 0 or PAGE_SIZE & (PAGE_SIZE - 1):
    raise RuntimeError("invalid system page size %d" % PAGE_SIZE)

ZERO_PAGE = b'\0' * PAGE_SIZE
PAGE_COMPRESSION_THRESHOLD = PAGE_SIZE * 7 // 8
MAX_REGION_SIZE = 4 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
PE_PARENT = 1 << 0
PE_PRESENT = 1 << 2
PE_PAYLOAD_ALIGNED = 1 << 3
MAP_SHARED = 1 << 0
MAP_HUGETLB = 0x40000
VMA_FILE_SHARED = 1 << 7
VMA_ANON_SHARED = 1 << 8
VMA_AREA_SYSVIPC = 1 << 10
VMA_EXT_PLUGIN = 1 << 27
CRTOOLS_IMAGES_V1_1 = 2
CRTOOLS_IMAGES_V1_2 = 3
CR_PARENT_LINK = 'parent'
TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


class CritTransformError(Exception):
    pass


def _pagemap_flags(entry):
    has_flags = 'flags' in entry
    flags = entry.get('flags', 0)

    if entry.get('in_parent'):
        flags |= PE_PARENT
    elif not has_flags:
        flags = PE_PRESENT

    return flags


def _load_image(path, image_metadata):
    source_metadata = _original_metadata(image_metadata, path)
    with _source_file(path, source_metadata) as image_file:
        return pycriu.images.load(image_file)


def _numeric_image_id(name, prefix):
    if not name.startswith(prefix) or not name.endswith('.img'):
        return None

    image_id = name[len(prefix):-len('.img')]
    if not image_id.isdigit():
        return None
    return int(image_id)


def _is_pagemap_image(name):
    shmem_id = _numeric_image_id(name, 'pagemap-shmem-')
    task_id = _numeric_image_id(name, 'pagemap-')
    return shmem_id is not None or task_id is not None


def _find_pagemaps(directory, image_metadata):
    """Find all pagemap files and their associated pages files."""
    pagemaps = []
    seen_pages_ids = set()

    for name in sorted(os.listdir(directory)):
        if not _is_pagemap_image(name):
            continue

        path = os.path.join(directory, name)
        pagemap = _load_image(path, image_metadata)

        if not pagemap['entries']:
            continue

        pages_id = pagemap['entries'][0].get('pages_id')
        if pages_id is None:
            raise CritTransformError("%s has no pages_id" % name)
        if pages_id in seen_pages_ids:
            raise CritTransformError("%s reuses pages_id %d" %
                                     (name, pages_id))
        seen_pages_ids.add(pages_id)

        pages_name = 'pages-%d.img' % pages_id
        pages_path = os.path.join(directory, pages_name)
        if not os.path.exists(pages_path):
            raise CritTransformError("%s refers to missing %s" %
                                     (name, pages_name))

        pagemaps.append((name, pages_name, pagemap))

    return pagemaps


def _merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _exceptional_vma_target(mm_name, task_pagemap, vma):
    flags = vma.get('flags', 0)
    status = vma.get('status', 0)
    if not (flags & MAP_HUGETLB or status & VMA_EXT_PLUGIN):
        return None

    start = vma.get('start')
    end = vma.get('end')
    if (not isinstance(start, int) or not isinstance(end, int) or
            start < 0 or end <= start or start % PAGE_SIZE or
            end % PAGE_SIZE):
        raise CritTransformError(
            "%s has an invalid exceptional VMA range %r-%r" %
            (mm_name, start, end))

    shared_status = VMA_FILE_SHARED | VMA_ANON_SHARED | VMA_AREA_SYSVIPC
    is_shared = flags & MAP_SHARED or status & shared_status
    if not is_shared:
        return task_pagemap, start, end

    shmid = vma.get('shmid')
    pgoff = vma.get('pgoff')
    vma_size = end - start
    if (not isinstance(shmid, int) or shmid < 0 or
            not isinstance(pgoff, int) or pgoff < 0 or
            pgoff % PAGE_SIZE or pgoff > UINT64_MAX - vma_size):
        raise CritTransformError(
            "%s has invalid shared exceptional VMA metadata" % mm_name)

    pagemap_name = 'pagemap-shmem-%d.img' % shmid
    return pagemap_name, pgoff, pgoff + vma_size


def _exceptional_pagemap_ranges(directory, pagemaps, image_metadata):
    """Return ranges which CRIU restore requires to remain raw.

    Task pagemaps use process virtual addresses. Shared-memory pagemaps use
    offsets into the shared object, so translate their VMAs through pgoff and
    shmid instead of assuming that the pagemap and mm image IDs are alike.
    """
    ranges = {pagemap_name: [] for pagemap_name, _, _ in pagemaps}
    pagemap_names = set(ranges)

    for name in sorted(os.listdir(directory)):
        task_id = _numeric_image_id(name, 'mm-')
        if task_id is None:
            continue

        mm_path = os.path.join(directory, name)
        mm_image = _load_image(mm_path, image_metadata)
        if not mm_image.get('entries'):
            raise CritTransformError("%s has no entries" % name)

        task_pagemap = 'pagemap-%d.img' % task_id
        for vma in mm_image['entries'][0].get('vmas', []):
            target = _exceptional_vma_target(name, task_pagemap, vma)
            if target is None:
                continue

            pagemap_name, range_start, range_end = target

            # File-backed mappings without pages and image subsets without the
            # corresponding pagemap do not have payload for CRIT to transform.
            if pagemap_name in pagemap_names:
                ranges[pagemap_name].append((range_start, range_end))

    return {name: _merge_ranges(pagemap_ranges)
            for name, pagemap_ranges in ranges.items()}


def _range_starts(ranges):
    return [start for start, _ in ranges]


def _address_in_ranges(address, ranges, starts):
    index = bisect.bisect_right(starts, address) - 1
    if index >= 0 and address < ranges[index][1]:
        return True

    # Native 32-bit x86 encode_pointer() sign-extends addresses through long,
    # while mm image VMA bounds remain their unsigned 32-bit values.
    if address >> 32 == UINT32_MAX:
        address &= UINT32_MAX
        index = bisect.bisect_right(starts, address) - 1
        return index >= 0 and address < ranges[index][1]
    return False


def _get_nr_pages(entry):
    return entry.get('nr_pages', entry.get('compat_nr_pages', 0))


def _entry_error(pagemap_name, index, message):
    raise CritTransformError("%s entry %d: %s" %
                             (pagemap_name, index, message))


def _aligned_payload_offset(offset):
    return (offset + PAGE_SIZE - 1) & -PAGE_SIZE


def _has_compression_metadata(entry):
    return (bool(entry.get('compressed_size')) or
            'total_compressed_size' in entry or
            'region_pages' in entry)


def _compressed_payload_size(pagemap_name, index, entry, nr_pages,
                             compressed_sizes):
    region_pages = entry.get('region_pages', 0)
    if not isinstance(region_pages, int) or region_pages < 0:
        _entry_error(pagemap_name, index,
                     "invalid region_pages %r" % region_pages)
    if region_pages * PAGE_SIZE > MAX_REGION_SIZE:
        _entry_error(pagemap_name, index,
                     "region size %d exceeds maximum %d bytes" %
                     (region_pages * PAGE_SIZE, MAX_REGION_SIZE))

    block_pages = region_pages or 1
    expected_blocks = (nr_pages + block_pages - 1) // block_pages
    if len(compressed_sizes) != expected_blocks:
        _entry_error(pagemap_name, index,
                     "%d compressed blocks, expected %d" %
                     (len(compressed_sizes), expected_blocks))

    payload_size = 0
    pages_done = 0
    for block_index, compressed_size in enumerate(compressed_sizes):
        pages = min(block_pages, nr_pages - pages_done)
        block_bytes = pages * PAGE_SIZE
        if not isinstance(compressed_size, int) or compressed_size < 0:
            _entry_error(pagemap_name, index,
                         "block %d has invalid size %r" %
                         (block_index, compressed_size))
        if compressed_size > block_bytes:
            _entry_error(
                pagemap_name, index,
                "block %d size %d exceeds its uncompressed size %d" %
                (block_index, compressed_size, block_bytes))
        payload_size += compressed_size
        if payload_size > UINT64_MAX:
            _entry_error(pagemap_name, index,
                         "compressed size sum overflows")
        pages_done += pages

    if pages_done != nr_pages:
        _entry_error(pagemap_name, index,
                     "%d pages covered, expected %d" %
                     (pages_done, nr_pages))

    recorded_size = entry.get('total_compressed_size')
    if recorded_size is not None and recorded_size != payload_size:
        _entry_error(pagemap_name, index,
                     "total_compressed_size %r does not match "
                     "block sum %d" % (recorded_size, payload_size))
    return payload_size


def _validate_pagemap(pagemap_name, pages_path, pagemap,
                      uncompressed_only=False):
    payload_size = 0

    for index, entry in enumerate(pagemap['entries'][1:], 1):
        nr_pages = _get_nr_pages(entry)
        flags = _pagemap_flags(entry)
        compressed_sizes = entry.get('compressed_size', [])
        has_compression_metadata = _has_compression_metadata(entry)

        if not isinstance(nr_pages, int) or nr_pages <= 0:
            _entry_error(pagemap_name, index,
                         "invalid page count %r" % nr_pages)
        if nr_pages > UINT64_MAX // PAGE_SIZE:
            _entry_error(pagemap_name, index, "page count overflows")

        vaddr = entry.get('vaddr')
        if not isinstance(vaddr, int) or vaddr < 0 or vaddr % PAGE_SIZE:
            _entry_error(pagemap_name, index,
                         "address %r is not page-aligned" % vaddr)
        if vaddr > UINT64_MAX - nr_pages * PAGE_SIZE:
            _entry_error(pagemap_name, index, "address range overflows")

        if flags & PE_PRESENT and flags & PE_PARENT:
            _entry_error(pagemap_name, index,
                         "PE_PRESENT and PE_PARENT are mutually exclusive")

        if flags & PE_PAYLOAD_ALIGNED and not flags & PE_PRESENT:
            _entry_error(pagemap_name, index,
                         "PE_PAYLOAD_ALIGNED is set on a non-present entry")

        if not flags & PE_PRESENT:
            if has_compression_metadata:
                _entry_error(pagemap_name, index,
                             "compression metadata is set on a "
                             "non-present entry")
            continue

        if uncompressed_only:
            if has_compression_metadata:
                _entry_error(pagemap_name, index,
                             "compression metadata is present in an "
                             "uncompressed checkpoint")
            if flags & PE_PAYLOAD_ALIGNED:
                _entry_error(pagemap_name, index,
                             "aligned compressed payload flag is present in "
                             "an uncompressed checkpoint")

        if not compressed_sizes:
            if has_compression_metadata:
                _entry_error(pagemap_name, index,
                             "incomplete compression metadata")
            entry_payload = nr_pages * PAGE_SIZE
        else:
            entry_payload = _compressed_payload_size(pagemap_name, index, entry, nr_pages,
                                                     compressed_sizes)

        if flags & PE_PAYLOAD_ALIGNED:
            payload_size = _aligned_payload_offset(payload_size)
        payload_size += entry_payload
        if payload_size > UINT64_MAX:
            raise CritTransformError(
                "%s payload size overflows" % pagemap_name)

    actual_size = os.stat(pages_path).st_size
    if payload_size != actual_size:
        raise CritTransformError(
            "%s describes %d payload bytes, but %s contains %d" %
            (pagemap_name, payload_size, os.path.basename(pages_path),
             actual_size))


def _validate_pagemaps(directory, pagemaps, uncompressed_only=False):
    for pagemap_name, pages_name, pagemap in pagemaps:
        pages_path = os.path.join(directory, pages_name)
        _validate_pagemap(pagemap_name, pages_path, pagemap,
                          uncompressed_only)


def _has_parent_reference(directory, pagemaps):
    parent_link = os.path.join(directory, CR_PARENT_LINK)
    if os.path.lexists(parent_link):
        return True

    for _, _, pagemap in pagemaps:
        if any(_pagemap_flags(entry) & PE_PARENT
               for entry in pagemap['entries'][1:]):
            return True
    return False


def _capture_file_metadata(path):
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise CritTransformError("image is not a regular file: %s" % path)
    if not hasattr(os, 'listxattr'):
        return metadata, []
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.ENOSYS):
            return metadata, []
        raise
    xattrs = [(name, os.getxattr(path, name, follow_symlinks=False))
              for name in names]
    return metadata, xattrs


def _is_transform_image(name):
    if not name.endswith('.img'):
        return False
    return (name == 'inventory.img' or
            name.startswith(('mm-', 'pagemap-', 'pages-')))


def _capture_image_metadata(directory, captured=None):
    """Snapshot metadata before image contents can update source atimes."""
    captured = dict(captured or {})
    for name in os.listdir(directory):
        if not _is_transform_image(name):
            continue
        path = os.path.join(directory, name)
        if path not in captured and os.path.isfile(path):
            captured[path] = _capture_file_metadata(path)
    return captured


def _original_metadata(captured, path):
    try:
        return captured[path]
    except KeyError as exc:
        raise CritTransformError(
            "image metadata was not captured before reading %s" % path
        ) from exc


@contextmanager
def _source_file(path, source_metadata):
    """Open an image without changing atime, restoring it on fallback."""
    flags = (os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) |
             getattr(os, 'O_NOFOLLOW', 0))
    restore_times = False
    noatime = getattr(os, 'O_NOATIME', None)
    if noatime is None:
        fd = os.open(path, flags)
        restore_times = True
    else:
        try:
            fd = os.open(path, flags | noatime)
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.EINVAL,
                                 errno.EOPNOTSUPP):
                raise
            fd = os.open(path, flags)
            restore_times = True

    try:
        source_stat, _ = source_metadata
        opened_stat = os.fstat(fd)
        if (opened_stat.st_dev, opened_stat.st_ino) != (
                source_stat.st_dev, source_stat.st_ino):
            raise CritTransformError(
                "image changed while preparing to read: %s" % path)
        with os.fdopen(fd, 'rb') as source:
            fd = -1
            try:
                yield source
            finally:
                source_failed = sys.exc_info()[0] is not None
                if restore_times:
                    try:
                        os.utime(source.fileno(),
                                 ns=(source_stat.st_atime_ns,
                                     source_stat.st_mtime_ns))
                    except OSError:
                        # Preserve a read/decode failure rather than replacing
                        # it with a secondary metadata-restoration error.
                        if not source_failed:
                            raise
    finally:
        if fd >= 0:
            os.close(fd)


@contextmanager
def _staged_file(path, source_metadata=None):
    directory = os.path.dirname(path)
    prefix = '.%s.crit-' % os.path.basename(path)
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, dir=directory)
    output = None

    try:
        if source_metadata is None:
            source_metadata = _capture_file_metadata(path)
        source_stat, xattrs = source_metadata
        # Keep mkstemp's restrictive mode while the replacement is partial.
        # Install the original metadata after writing: content writes and
        # chown can clear capabilities, set-id bits, or ACL information.
        original_owner = (source_stat.st_uid, source_stat.st_gid)
        original_mode = stat.S_IMODE(source_stat.st_mode)
        original_times = (source_stat.st_atime_ns,
                          source_stat.st_mtime_ns)
        output = os.fdopen(fd, 'wb')
        fd = -1
        yield output, tmp_path
        output.flush()
        os.fchown(output.fileno(), *original_owner)
        os.fchmod(output.fileno(), original_mode)
        # Replacing the inode would otherwise silently discard POSIX ACLs,
        # security labels, and other extended metadata carried as xattrs.
        for name, value in xattrs:
            os.setxattr(output.fileno(), name, value)
        # Content writes and metadata installation update the replacement's
        # timestamps. Restore the source values only after those operations.
        os.utime(output.fileno(), ns=original_times)
        os.fsync(output.fileno())
        try:
            output.close()
        finally:
            output = None
    except BaseException:
        if output is not None:
            try:
                output.close()
            except OSError:
                pass  # Preserve the transformation error being handled.
            output = None
        elif fd >= 0:
            os.close(fd)
            fd = -1
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass  # The failed operation may already have removed it.
        except OSError as cleanup_exc:
            # Do not replace the transformation error with a secondary
            # failure to remove its incomplete temporary file.
            print("Warning: unable to remove temporary file %s: %s" %
                  (tmp_path, cleanup_exc), file=sys.stderr)
        raise
    finally:
        if output is not None:
            output.close()
        elif fd >= 0:
            os.close(fd)


def _stage_image(path, image, source_metadata=None):
    with _staged_file(path, source_metadata) as (output, tmp_path):
        pycriu.images.dump(image, output)
    return tmp_path


@contextmanager
def _stage_file_update(staged, path, image_metadata):
    source_metadata = _original_metadata(image_metadata, path)
    with _staged_file(path, source_metadata) as staged_file:
        output, tmp_path = staged_file
        with _source_file(path, source_metadata) as source:
            yield source, output
    staged.append((path, tmp_path))


def _stage_image_update(staged, path, image, image_metadata):
    source_metadata = _original_metadata(image_metadata, path)
    tmp_path = _stage_image(path, image, source_metadata)
    staged.append((path, tmp_path))


def _remove_file(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass  # Cleanup is idempotent.


def _cleanup_staged_files(staged):
    errors = []
    for _, tmp_path in staged:
        try:
            _remove_file(tmp_path)
        except OSError as exc:
            errors.append((tmp_path, exc))
    return errors


def _report_cleanup_errors(errors):
    for path, exc in errors:
        print("Warning: unable to remove temporary file %s: %s" %
              (path, exc), file=sys.stderr)


def _make_rollback_link(path):
    directory = os.path.dirname(path)
    prefix = '.%s.crit-rollback-' % os.path.basename(path)
    fd, rollback_path = tempfile.mkstemp(prefix=prefix, dir=directory)
    os.close(fd)
    os.unlink(rollback_path)
    try:
        os.link(path, rollback_path)
    except BaseException:
        try:
            _remove_file(rollback_path)
        except OSError as cleanup_exc:
            print("Warning: unable to remove transaction file %s: %s" %
                  (rollback_path, cleanup_exc), file=sys.stderr)
        raise
    return rollback_path


def _fsync_directories(paths):
    directories = {os.path.dirname(path) or '.' for path in paths}
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)

    for directory in directories:
        fd = os.open(directory, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextmanager
def _commit_signal_handlers():
    previous = {}
    state = {
        'committed': False,
        'received': set(),
    }

    def interrupted(signum, _frame):
        # A durable replacement must still be reported as successful when a
        # signal arrives while printing statistics or returning from the CLI.
        if state['committed']:
            return
        # The first signal starts synchronous exception cleanup. Repeated
        # signals must not interrupt that cleanup and strand staged files.
        if state['received']:
            return
        state['received'].add(signum)
        raise CritTransformError(
            "commit interrupted by %s" % signal.Signals(signum).name)

    # Turn termination signals into exceptions while images are staged.
    # _commit_staged() can then put every original image back before the
    # command terminates.
    for signum in TERMINATION_SIGNALS:
        old_handler = signal.getsignal(signum)
        if old_handler == signal.SIG_IGN:
            continue
        previous[signum] = old_handler
        signal.signal(signum, interrupted)
    try:
        yield state
    finally:
        for signum, old_handler in previous.items():
            signal.signal(signum, old_handler)


@contextmanager
def _deferred_commit_signals():
    previous = {}
    received = []

    def interrupted(signum, _frame):
        # Do not raise between a rename and the bookkeeping which makes that
        # rename recoverable. The transaction checks this list after every
        # image has reached a consistent on-disk state.
        if signum not in received:
            received.append(signum)

    for signum in TERMINATION_SIGNALS:
        old_handler = signal.getsignal(signum)
        if old_handler == signal.SIG_IGN:
            continue
        previous[signum] = old_handler
        signal.signal(signum, interrupted)
    try:
        yield received
    finally:
        for signum, old_handler in previous.items():
            signal.signal(signum, old_handler)


def _verify_image_identity(path, current_path, image_metadata):
    if image_metadata is None:
        return

    source_stat, _ = _original_metadata(image_metadata, path)
    current_stat = os.stat(current_path, follow_symlinks=False)
    if (current_stat.st_dev, current_stat.st_ino) != (
            source_stat.st_dev, source_stat.st_ino):
        raise CritTransformError(
            "image changed while preparing to replace: %s" % path)


def _commit_staged(staged, in_place, signal_state=None,
                   image_metadata=None):
    rollback_links = {}
    replacement_started = set()
    backed_up_paths = set()
    image_paths = [path for path, _ in staged]

    with _deferred_commit_signals() as interrupted:
        try:
            if in_place:
                # Keep every original before replacing any image so a later
                # rename failure can be rolled back across the complete set.
                for path, _ in staged:
                    rollback_links[path] = _make_rollback_link(path)
                    _verify_image_identity(
                        path, rollback_links[path], image_metadata)
            else:
                # link() fails atomically with EEXIST, closing the race between
                # a backup preflight and rename-overwrite. These links are both
                # the requested backups and rollback sources until commit.
                for path, _ in staged:
                    backup_path = path + '.bak'
                    try:
                        os.link(path, backup_path)
                    except FileExistsError as exc:
                        raise CritTransformError(
                            "refusing to overwrite existing backup: %s" %
                            backup_path) from exc
                    backed_up_paths.add(path)
                    _verify_image_identity(path, backup_path, image_metadata)

            # All rollback sources now refer to the captured originals.
            # Verify that every live name still does before changing any
            # pathname, then narrow the remaining race with a per-file check.
            for path, _ in staged:
                _verify_image_identity(path, path, image_metadata)
            _fsync_directories(image_paths)

            for path, tmp_path in staged:
                _verify_image_identity(path, path, image_metadata)
                # Mark the path recoverable before entering the syscall.  A
                # Python signal or injected exception can run immediately
                # after rename(2) changed the directory but before the call
                # appears to return to this frame.
                replacement_started.add(path)
                os.replace(tmp_path, path)
            _fsync_directories(image_paths)

            if interrupted:
                signal_names = ', '.join(signal.Signals(signum).name
                                         for signum in interrupted)
                raise CritTransformError(
                    "commit interrupted by %s" % signal_names)
            if signal_state is not None:
                signal_state['committed'] = True
        except BaseException as exc:
            rollback_errors = []
            recovery_sources = set()
            for path, _ in reversed(staged):
                if path not in replacement_started:
                    continue
                recovery_source = (path + '.bak' if not in_place else
                                   rollback_links.get(path))
                if recovery_source is None:
                    continue
                try:
                    os.replace(recovery_source, path)
                except OSError as rollback_exc:
                    rollback_errors.append(
                        "%s (original retained at %s): %s" %
                        (path, recovery_source, rollback_exc))
                    recovery_sources.add(recovery_source)

            # Backups for paths which were never replaced are no longer part
            # of a failed operation. A backup that could not be renamed back is
            # deliberately preserved as the last recoverable original copy.
            if not in_place:
                for path in backed_up_paths:
                    backup_path = path + '.bak'
                    if backup_path in recovery_sources:
                        continue
                    try:
                        os.unlink(backup_path)
                    except FileNotFoundError:
                        pass  # Another cleanup path already removed it.
                    except OSError as rollback_exc:
                        rollback_errors.append("%s: %s" %
                                               (backup_path, rollback_exc))

            try:
                _fsync_directories(image_paths)
            except OSError as rollback_exc:
                rollback_errors.append("directory sync: %s" % rollback_exc)

            for path, tmp_path in staged:
                try:
                    _remove_file(tmp_path)
                except OSError as cleanup_exc:
                    rollback_errors.append("%s: %s" %
                                           (tmp_path, cleanup_exc))
                rollback_path = rollback_links.get(path)
                if (rollback_path is not None and
                        rollback_path not in recovery_sources):
                    try:
                        _remove_file(rollback_path)
                    except OSError as cleanup_exc:
                        rollback_errors.append("%s: %s" %
                                               (rollback_path, cleanup_exc))

            if rollback_errors:
                raise CritTransformError(
                    "commit failed (%s); rollback also failed for %s" %
                    (exc, ', '.join(rollback_errors)))
            if not isinstance(exc, Exception):
                raise
            raise CritTransformError(
                "commit failed; original images were restored: %s" % exc)

        if in_place:
            # Keep signals deferred until rollback links have been removed and
            # that removal is durable. Once the replacement set has committed,
            # a signal arriving during this best-effort cleanup must not make
            # the command report failure for an image set it already installed.
            cleanup_failed = False
            for rollback_path in rollback_links.values():
                try:
                    os.unlink(rollback_path)
                except OSError as exc:
                    cleanup_failed = True
                    print("Warning: unable to remove transaction file %s: %s" %
                          (rollback_path, exc), file=sys.stderr)
            if not cleanup_failed:
                try:
                    _fsync_directories(image_paths)
                except OSError as exc:
                    print("Warning: unable to sync image directory: %s" % exc,
                          file=sys.stderr)


def _copy_exact(source, output, size, pages_name):
    remaining = size
    while remaining:
        data = source.read(min(remaining, COPY_CHUNK_SIZE))
        if not data:
            raise CritTransformError("short read in %s" % pages_name)
        output.write(data)
        remaining -= len(data)


def _read_exact(source, size, pages_name):
    chunks = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise CritTransformError("short read in %s" % pages_name)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def _write_zeros(output, size):
    remaining = size
    while remaining:
        chunk = min(remaining, len(ZERO_PAGE))
        output.write(ZERO_PAGE[:chunk])
        remaining -= chunk


def _align_output_payload(output):
    padding = _aligned_payload_offset(output.tell()) - output.tell()
    _write_zeros(output, padding)
    return padding


def _skip_input_padding(source, pages_name):
    padding = _aligned_payload_offset(source.tell()) - source.tell()
    if padding:
        _read_exact(source, padding, pages_name)
    return padding


def _command_failed(action, exc, staged):
    cleanup_errors = _cleanup_staged_files(staged)
    print("Error: failed to %s checkpoint: %s" % (action, exc),
          file=sys.stderr)
    _report_cleanup_errors(cleanup_errors)
    return 1


def _load_lz4_block():
    try:
        from lz4 import block as lz4_block
    except ImportError:
        print("Error: lz4 Python package is required.\n"
              "Install with: pip install lz4", file=sys.stderr)
        return None
    return lz4_block


def _load_inventory(directory):
    inventory_path = os.path.join(directory, 'inventory.img')
    image_metadata = {
        inventory_path: _capture_file_metadata(inventory_path),
    }
    inventory = _load_image(inventory_path, image_metadata)
    return inventory_path, inventory, image_metadata


def _inventory_compression_mode(inventory):
    if not inventory.get('entries'):
        raise CritTransformError("inventory has no entries")

    inventory_entry = inventory['entries'][0]
    image_version = inventory_entry.get('img_version')
    if image_version not in (CRTOOLS_IMAGES_V1_1, CRTOOLS_IMAGES_V1_2):
        raise CritTransformError(
            "inventory has unsupported image version %r" % image_version)

    compression_mode = inventory_entry.get('compress', 0)
    if compression_mode not in (0, 1, 2):
        raise CritTransformError(
            "inventory has invalid compression mode %r" % compression_mode)
    if compression_mode and image_version != CRTOOLS_IMAGES_V1_2:
        raise CritTransformError(
            "inventory image version %r cannot contain compressed pages" %
            image_version)
    return compression_mode


def _encode_page(page, force_raw, lz4_block, acceleration):
    if force_raw:
        return page, PAGE_SIZE

    compressed = lz4_block.compress(
        page, mode='fast', store_size=False, acceleration=acceleration)
    if len(compressed) >= PAGE_COMPRESSION_THRESHOLD:
        return page, PAGE_SIZE
    return compressed, len(compressed)


def _remove_compression_metadata(entry):
    entry.pop('compressed_size', None)
    entry.pop('total_compressed_size', None)
    entry.pop('region_pages', None)


def _compress_pages_image(pages_in, pages_out, pages_name, pagemap,
                          raw_ranges, acceleration, lz4_block):
    total_pages = 0
    input_size = 0
    output_size = 0
    raw_range_starts = _range_starts(raw_ranges)

    for entry in pagemap['entries'][1:]:
        nr_pages = _get_nr_pages(entry)
        flags = _pagemap_flags(entry)

        # Only PE_PRESENT entries have payload in pages-*.img.
        if not flags & PE_PRESENT:
            continue

        compressed_sizes = []
        total_compressed_size = 0
        payload_started = False

        for page_index in range(nr_pages):
            page = _read_exact(pages_in, PAGE_SIZE, pages_name)
            input_size += PAGE_SIZE
            total_pages += 1

            if page == ZERO_PAGE:
                compressed_sizes.append(0)
                continue

            page_vaddr = entry['vaddr'] + page_index * PAGE_SIZE
            force_raw = _address_in_ranges(page_vaddr, raw_ranges, raw_range_starts)
            payload, stored_size = _encode_page(page, force_raw, lz4_block, acceleration)

            if stored_size == PAGE_SIZE and not payload_started:
                output_size += _align_output_payload(pages_out)
                flags |= PE_PAYLOAD_ALIGNED
                entry['flags'] = flags

            payload_started = True
            pages_out.write(payload)
            compressed_sizes.append(stored_size)
            total_compressed_size += stored_size
            output_size += stored_size

        if all(size == PAGE_SIZE for size in compressed_sizes):
            # The staged payload is already an ordinary contiguous pages
            # image, so avoid restore-side metadata work.
            _remove_compression_metadata(entry)
        else:
            entry['compressed_size'] = compressed_sizes
            entry['total_compressed_size'] = total_compressed_size

    return total_pages, input_size, output_size


def _decode_block(pages_in, pages_out, compressed_size, block_bytes,
                  pages_name, lz4_block):
    if compressed_size == 0:
        _write_zeros(pages_out, block_bytes)
        return
    if compressed_size == block_bytes:
        _copy_exact(pages_in, pages_out, compressed_size, pages_name)
        return

    data = _read_exact(pages_in, compressed_size, pages_name)
    try:
        block = lz4_block.decompress(data, uncompressed_size=block_bytes)
    except Exception as exc:
        raise CritTransformError(
            "decompression failed in %s: %s" % (pages_name, exc))
    if len(block) != block_bytes:
        raise CritTransformError(
            "decompression in %s produced %d bytes, expected %d" %
            (pages_name, len(block), block_bytes))
    pages_out.write(block)


def _decompress_pages_image(pages_in, pages_out, pages_name, pagemap,
                            lz4_block):
    total_pages = 0
    input_size = 0
    output_size = 0

    for entry in pagemap['entries'][1:]:
        nr_pages = _get_nr_pages(entry)
        flags = _pagemap_flags(entry)

        # Only PE_PRESENT entries have payload in pages-*.img.
        if not flags & PE_PRESENT:
            continue

        if flags & PE_PAYLOAD_ALIGNED:
            input_size += _skip_input_padding(pages_in, pages_name)
            entry['flags'] = flags & ~PE_PAYLOAD_ALIGNED

        compressed_sizes = entry.get('compressed_size')
        if not compressed_sizes:
            uncompressed_size = nr_pages * PAGE_SIZE
            _copy_exact(pages_in, pages_out, uncompressed_size, pages_name)
            input_size += uncompressed_size
            output_size += uncompressed_size
            total_pages += nr_pages
            continue

        # region_pages > 0 means each compressed_size entry covers up to
        # region_pages pages as one LZ4 block.
        region_pages = entry.get('region_pages', 0)
        remaining_pages = nr_pages

        for compressed_size in compressed_sizes:
            block_pages = min(region_pages or 1, remaining_pages)
            block_bytes = block_pages * PAGE_SIZE
            _decode_block(pages_in, pages_out, compressed_size, block_bytes,
                          pages_name, lz4_block)
            input_size += compressed_size
            output_size += block_bytes
            total_pages += block_pages
            remaining_pages -= block_pages

        if remaining_pages:
            raise CritTransformError(
                "block page count mismatch in %s (%d pages unaccounted)" %
                (pages_name, remaining_pages))

        _remove_compression_metadata(entry)

    return total_pages, input_size, output_size


def _stage_compressed_pagemap(staged, directory, pagemap_name, pages_name,
                              pagemap, image_metadata, raw_ranges,
                              acceleration, lz4_block):
    pagemap_path = os.path.join(directory, pagemap_name)
    pages_path = os.path.join(directory, pages_name)

    with _stage_file_update(staged, pages_path, image_metadata) as files:
        pages_in, pages_out = files
        stats = _compress_pages_image(
            pages_in, pages_out, pages_name, pagemap, raw_ranges,
            acceleration, lz4_block)

    _stage_image_update(staged, pagemap_path, pagemap, image_metadata)
    return stats


def _stage_decompressed_pagemap(staged, directory, pagemap_name, pages_name,
                                pagemap, image_metadata, lz4_block):
    pagemap_path = os.path.join(directory, pagemap_name)
    pages_path = os.path.join(directory, pages_name)

    with _stage_file_update(staged, pages_path, image_metadata) as files:
        pages_in, pages_out = files
        stats = _decompress_pages_image(
            pages_in, pages_out, pages_name, pagemap, lz4_block)

    _stage_image_update(staged, pagemap_path, pagemap, image_metadata)
    return stats


def compress_cmd(opts):
    lz4_block = _load_lz4_block()
    if lz4_block is None:
        return 1

    directory = opts['dir']
    in_place = opts.get('in_place', False)
    acceleration = opts.get('acceleration', 1)
    staged = []
    stats = []

    try:
        if acceleration < 1 or acceleration > 65537:
            raise CritTransformError(
                "LZ4 acceleration must be between 1 and 65537")

        inventory_path, inventory, image_metadata = _load_inventory(directory)
        compression_mode = _inventory_compression_mode(inventory)
        if compression_mode:
            print("Checkpoint in %s is already compressed" % directory)
            return 0

        image_metadata = _capture_image_metadata(directory, image_metadata)
        pagemaps = _find_pagemaps(directory, image_metadata)
        if not pagemaps:
            print("No pagemap files found in %s" % directory)
            return 0

        _validate_pagemaps(directory, pagemaps, uncompressed_only=True)
        exceptional_ranges = _exceptional_pagemap_ranges(directory, pagemaps, image_metadata)

        print("Compressing checkpoint in %s" % directory)

        for pagemap_name, pages_name, pagemap in pagemaps:
            pagemap_stats = _stage_compressed_pagemap(
                staged, directory, pagemap_name, pages_name, pagemap,
                image_metadata, exceptional_ranges[pagemap_name],
                acceleration, lz4_block)
            stats.append((pagemap_name,) + pagemap_stats)

        inventory['entries'][0]['compress'] = 1  # COMPRESS_PER_PAGE
        inventory['entries'][0]['img_version'] = CRTOOLS_IMAGES_V1_2
        _stage_image_update(staged, inventory_path, inventory, image_metadata)

        commit_signal_state = opts.get('_commit_signal_state')
        _commit_staged(staged, in_place, commit_signal_state,
                       image_metadata)
    except Exception as exc:
        return _command_failed("compress", exc, staged)
    except BaseException:
        _report_cleanup_errors(_cleanup_staged_files(staged))
        raise

    for pagemap_name, total_pages, input_size, output_size in stats:
        if input_size:
            saved = (1 - output_size / input_size) * 100
            print("  %s: %d pages (%dK -> %dK, %.1f%% saved)" %
                  (pagemap_name, total_pages, input_size // 1024,
                   output_size // 1024, saved))

    print("Done")
    return 0


def decompress_cmd(opts):
    lz4_block = _load_lz4_block()
    if lz4_block is None:
        return 1

    directory = opts['dir']
    in_place = opts.get('in_place', False)
    staged = []
    stats = []

    try:
        inventory_path, inventory, image_metadata = _load_inventory(directory)
        compression_mode = _inventory_compression_mode(inventory)
        if not compression_mode:
            print("Checkpoint in %s is already decompressed" % directory)
            return 0

        image_metadata = _capture_image_metadata(directory, image_metadata)
        pagemaps = _find_pagemaps(directory, image_metadata)
        if not pagemaps:
            print("No pagemap files found in %s" % directory)
            return 0

        _validate_pagemaps(directory, pagemaps)
        has_parent_reference = _has_parent_reference(directory, pagemaps)

        print("Decompressing checkpoint in %s" % directory)

        for pagemap_name, pages_name, pagemap in pagemaps:
            pagemap_stats = _stage_decompressed_pagemap(
                staged, directory, pagemap_name, pages_name, pagemap,
                image_metadata, lz4_block)
            stats.append((pagemap_name,) + pagemap_stats)

        inventory['entries'][0].pop('compress', None)
        inventory['entries'][0].pop('compress_region_size', None)
        if (not has_parent_reference and
                inventory['entries'][0].get('img_version') ==
                CRTOOLS_IMAGES_V1_2):
            inventory['entries'][0]['img_version'] = CRTOOLS_IMAGES_V1_1
        _stage_image_update(staged, inventory_path, inventory, image_metadata)

        commit_signal_state = opts.get('_commit_signal_state')
        _commit_staged(staged, in_place, commit_signal_state,
                       image_metadata)
    except Exception as exc:
        return _command_failed("decompress", exc, staged)
    except BaseException:
        _report_cleanup_errors(_cleanup_staged_files(staged))
        raise

    for pagemap_name, total_pages, input_size, output_size in stats:
        print("  %s: %d pages (%dK -> %dK)" %
              (pagemap_name, total_pages, input_size // 1024,
               output_size // 1024))

    print("Done")
    return 0


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

    # Compress
    compress_parser = subparsers.add_parser(
        'compress', help='Compress memory pages in a checkpoint directory')
    compress_parser.add_argument('dir')
    compress_parser.add_argument('--in-place', action='store_true',
                                 help='Skip creating backup files')
    compress_parser.add_argument('--acceleration', type=int, default=1,
                                 help='LZ4 acceleration (1=default, higher=faster)')
    compress_parser.set_defaults(func=compress_cmd)

    # Decompress
    decompress_parser = subparsers.add_parser(
        'decompress', help='Decompress memory pages in a checkpoint directory')
    decompress_parser.add_argument('dir')
    decompress_parser.add_argument('--in-place', action='store_true',
                                    help='Skip creating backup files')
    decompress_parser.set_defaults(func=decompress_cmd)

    opts = vars(parser.parse_args())

    if not opts:
        sys.stderr.write(parser.format_usage())
        sys.stderr.write("crit: error: too few arguments\n")
        sys.exit(1)

    if opts["func"] in (compress_cmd, decompress_cmd):
        # Convert termination into a Python exception for the complete
        # transformation, including staging. Context managers can then remove
        # the current temporary file and _command_failed() removes earlier
        # staged outputs before returning a failure status.
        with _commit_signal_handlers() as signal_state:
            opts['_commit_signal_state'] = signal_state
            ret = opts["func"](opts)
    else:
        ret = opts["func"](opts)
    if ret:
        sys.exit(ret)


if __name__ == '__main__':
    main()
