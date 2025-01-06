import os
import tempfile

id_str = ""


def create_fds():
    tdir = tempfile.mkdtemp("zdtm.inhfd.XXXXXX")
    if os.system("mount -t tmpfs zdtm.inhfd %s" % tdir) != 0:
        raise Exception("Unable to mount tmpfs")
    tfifo = os.path.join(tdir, "test_fifo")
    os.mkfifo(tfifo)
    fd2 = open(tfifo, "w+b", buffering=0)
    fd1 = open(tfifo, "rb")
    os.system("umount -l %s" % tdir)
    os.rmdir(tdir)

    mnt_id = -1
    with open("/proc/self/fdinfo/%d" % fd1.fileno()) as f:
        for line in f:
            line = line.split()
            if line[0] == "mnt_id:":
                mnt_id = int(line[1])
                break
        else:
            raise Exception("Unable to find mnt_id")

    global id_str
    id_str = "file[%x:%x]" % (mnt_id, os.fstat(fd1.fileno()).st_ino)

    return [(fd2, fd1)]


def filename(pipef):
    return id_str


def dump_opts(sockf):
    return ["--external", id_str]
