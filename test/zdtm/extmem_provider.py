import array
import fcntl
import mmap
import os
import pathlib
import socket
import sys


class ExtmemProvider:
    """Test-only external-memory provider for a ZDTM restore."""

    _shared_memfd_name = "/memfd:zdtm-extmem-shared"

    def __init__(self, pid, image_fallback=False, require_shared=True, vma_fallback=False):
        self.root_pid = int(pid)
        self.memory, self.shared = self._snapshot_memory(pid)
        self.image_fallback = image_fallback
        self.require_shared = require_shared
        self.vma_fallback = vma_fallback
        if require_shared and not self.shared:
            raise RuntimeError("test shared memfd was not found")
        self.client = None
        self.pid = None

    @staticmethod
    def _snapshot_memory(pid):
        memory = []
        shared = {}
        page_sizes = {}
        with open(f"/proc/{pid}/smaps") as smaps:
            for line in smaps:
                fields = line.split()
                if "-" in fields[0]:
                    base = int(fields[0].split("-")[0], 16)
                elif fields[0] == "KernelPageSize:":
                    page_sizes[base] = int(fields[1]) * 1024
        with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            for line in maps:
                fields = line.split(maxsplit=5)
                name = fields[5].strip() if len(fields) == 6 else ""
                private_anonymous = fields[1].endswith("p") and (
                    not name or name == "[heap]" or name.startswith(("[anon:", "/anon_hugepage"))
                )
                shared_memfd = fields[1].endswith("s") and name.startswith(
                    ExtmemProvider._shared_memfd_name
                )
                if not private_anonymous and not shared_memfd:
                    continue
                start, end = (int(value, 16) for value in fields[0].split("-"))
                content = os.pread(mem.fileno(), end - start, start)
                if len(content) != end - start:
                    raise RuntimeError(f"short read at {start:#x}")
                if private_anonymous:
                    flags = 0
                    if name.startswith("/anon_hugepage"):
                        flags = os.MFD_HUGETLB | ((page_sizes[start].bit_length() - 1) << 26)
                    memory.append((start, content, flags))
                else:
                    shared[int(fields[4])] = content
        return memory, shared

    @staticmethod
    def _varint(value):
        result = bytearray()
        while value > 0x7f:
            result.append((value & 0x7f) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    @staticmethod
    def _parse_varint(data, offset):
        value = shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, offset
            shift += 7

    @classmethod
    def _fields(cls, data):
        result = {}
        offset = 0
        while offset < len(data):
            tag, offset = cls._parse_varint(data, offset)
            number, wire_type = tag >> 3, tag & 7
            if wire_type == 0:
                value, offset = cls._parse_varint(data, offset)
            elif wire_type == 2:
                length, offset = cls._parse_varint(data, offset)
                value, offset = data[offset:offset + length], offset + length
            else:
                raise RuntimeError(f"unsupported protobuf wire type {wire_type}")
            result[number] = value
        return result

    @staticmethod
    def _memory_at(memory, start, length):
        for base, content, flags in memory:
            offset = start - base
            if offset >= 0 and offset + length <= len(content):
                return content[offset:offset + length], flags
        return None

    def _send(self, sock, status, fd=None):
        if status < 0:
            status &= (1 << 64) - 1
        ancillary = []
        if fd is not None:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd])))
        sock.sendmsg([b"\x08" + self._varint(status)], ancillary)

    def _serve(self, sock, image_dir):
        images = set(os.listdir(image_dir))
        missing_images = set()
        missing_requested = False
        if self.image_fallback:
            for name in {"seccomp.img", "memfd.img", "remap-fpath.img"} - images:
                with open(os.path.join(image_dir, name), "wb") as stale:
                    stale.write(b"stale optional image")
                missing_images.add(name)
        requested_vmas = 0
        requested_shared = set()
        declined_image = False
        served_image = False
        declined_vma = False
        try:
            while True:
                packet, _, flags, _ = sock.recvmsg(8192)
                if flags & socket.MSG_TRUNC:
                    raise RuntimeError("truncated provider request")
                request = self._fields(packet)
                op = request[1]
                if op == 1:  # INIT
                    self._send(sock, 0)
                elif op == 2:  # OPEN_IMAGE
                    name = self._fields(request[2])[1].decode()
                    if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                        raise RuntimeError(f"invalid image name {name!r}")
                    if name not in images:
                        missing_requested |= name in missing_images
                        self._send(sock, -2)  # -ENOENT: do not use a local file.
                        continue
                    if self.image_fallback and not declined_image:
                        declined_image = True
                        self._send(sock, -95)  # -ENOTSUP: use CRIU's local image.
                        continue
                    fd = os.open(os.path.join(image_dir, name), os.O_RDONLY)
                    try:
                        self._send(sock, 0, fd)
                    finally:
                        os.close(fd)
                    served_image = True
                elif op == 3:  # GET_VMA
                    vma = self._fields(request[3])
                    if self.vma_fallback or vma[1] != self.root_pid:
                        declined_vma = True
                        self._send(sock, -95)  # -ENOTSUP: use CRIU's local restore.
                        continue
                    source = self._memory_at(self.memory, vma[3], vma[4])
                    if source is None:
                        raise RuntimeError("GET_VMA offered a non-anonymous mapping")
                    content, flags = source
                    fd = os.memfd_create("zdtm-extmem-private", os.MFD_ALLOW_SEALING | flags)
                    try:
                        os.ftruncate(fd, vma[4])
                        if flags:
                            with mmap.mmap(fd, vma[4], flags=mmap.MAP_SHARED,
                                           prot=mmap.PROT_WRITE) as target:
                                target[:] = content
                        else:
                            os.write(fd, content)
                        self._send(sock, 0, fd)
                    finally:
                        os.close(fd)
                    requested_vmas += 1
                elif op == 4:  # GET_SHARED
                    shared = self._fields(request[4])
                    content = self.shared.get(shared[1])
                    if content is None or len(content) != shared[2]:
                        self._send(sock, -95)  # -ENOTSUP: use CRIU's local image.
                        continue
                    fd = os.memfd_create("zdtm-extmem-shared", os.MFD_ALLOW_SEALING)
                    try:
                        os.ftruncate(fd, shared[2])
                        os.write(fd, content)
                        self._send(sock, 0, fd)
                    finally:
                        os.close(fd)
                    requested_shared.add(shared[1])
                elif op == 7:  # WAIT_READY
                    self._send(sock, 0)
                elif op == 5:  # COMMIT
                    if self.vma_fallback and not declined_vma:
                        raise RuntimeError("provider did not test private VMA fallback")
                    if not self.vma_fallback and not requested_vmas:
                        raise RuntimeError("provider did not serve private memory")
                    if self.require_shared and requested_shared != set(self.shared):
                        raise RuntimeError("provider did not serve shared memory")
                    if self.image_fallback and (not declined_image or not served_image):
                        raise RuntimeError("provider did not test image fallback")
                    if self.image_fallback and not missing_requested:
                        raise RuntimeError("provider did not test an absent optional image")
                    self._send(sock, 0)
                    return
                elif op == 6:  # ABORT
                    self._send(sock, 0)
                    raise RuntimeError("CRIU aborted provider restore")
                else:
                    raise RuntimeError(f"unexpected provider operation {op}")
        finally:
            for name in missing_images:
                os.unlink(os.path.join(image_dir, name))
            sock.close()

    def start(self, image_dir):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fdflags = fcntl.fcntl(client.fileno(), fcntl.F_GETFD)
        fcntl.fcntl(client.fileno(), fcntl.F_SETFD, fdflags & ~fcntl.FD_CLOEXEC)
        self.pid = os.fork()
        if self.pid == 0:
            client.close()
            try:
                self._serve(server, image_dir)
            except Exception as error:
                print(f"extmem provider: {error}", file=sys.stderr)
                os._exit(1)
            os._exit(0)
        server.close()
        self.client = client
        return ["--inherit-fd", f"fd[{client.fileno()}]:extmem-provider"]

    def finish(self):
        self.client.close()
        self.client = None
        _, status = os.waitpid(self.pid, 0)
        self.pid = None
        if status:
            raise RuntimeError(f"extmem provider exited with status {status}")
