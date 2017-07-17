#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sched.h>
#include <linux/aio_abi.h>
#include <sys/mount.h>

#include "../soccr/soccr.h"

#include "types.h"
#include "fdinfo.h"
#include "sockets.h"
#include "crtools.h"
#include "log.h"
#include "util-pie.h"
#include "prctl.h"
#include "files.h"
#include "sk-inet.h"
#include "proc_parse.h"
#include "mount.h"
#include "tty.h"
#include <compel/ptrace.h>
#include "ptrace-compat.h"
#include "kerndat.h"
#include "timerfd.h"
#include "util.h"
#include "tun.h"
#include "namespaces.h"
#include "pstree.h"
#include "cr_options.h"
#include "libnetlink.h"
#include "net.h"
#include "restorer.h"
#include "uffd.h"

static char *feature_name(int (*func)());

static int check_tty(void)
{
	int master = -1, slave = -1;
	const int lock = 1;
	struct termios t;
	char *slavename;
	int ret = -1;

	if (ARRAY_SIZE(t.c_cc) < TERMIOS_NCC) {
		pr_msg("struct termios has %d @c_cc while "
			"at least %d expected.\n",
			(int)ARRAY_SIZE(t.c_cc),
			TERMIOS_NCC);
		goto out;
	}

	master = open("/dev/ptmx", O_RDWR);
	if (master < 0) {
		pr_perror("Can't open /dev/ptmx");
		goto out;
	}

	if (ioctl(master, TIOCSPTLCK, &lock)) {
		pr_perror("Can't lock pty master");
		goto out;
	}

	slavename = ptsname(master);
	slave = open(slavename, O_RDWR);
	if (slave < 0) {
		if (errno != EIO) {
			pr_perror("Unexpected error on locked pty");
			goto out;
		}
	} else {
		pr_err("Managed to open locked pty.\n");
		goto out;
	}

	ret = 0;
out:
	close_safe(&master);
	close_safe(&slave);
	return ret;
}

static int check_map_files(void)
{
	int ret;

	ret = access("/proc/self/map_files", R_OK);
	if (!ret)
		return 0;

	pr_perror("/proc/<pid>/map_files is inaccessible");
	return -1;
}

static int check_sock_diag(void)
{
	int ret;
	struct ns_id ns;

	ns.ns_pid = 0;
	ns.type = NS_CRIU;
	ns.net.nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (ns.net.nlsk < 0) {
		pr_perror("Can't make diag socket for check");
		return -1;
	}

	ret = collect_sockets(&ns);
	if (!ret)
		return 0;

	pr_msg("The sock diag infrastructure is incomplete.\n");
	pr_msg("Make sure you have:\n");
	pr_msg(" 1. *_DIAG kernel config options turned on;\n");
	pr_msg(" 2. *_diag.ko modules loaded (if compiled as modules).\n");
	return -1;
}

static int check_ns_last_pid(void)
{
	int ret;

	ret = access("/proc/" LAST_PID_PATH, W_OK);
	if (!ret)
		return 0;

	pr_perror("%s sysctl is inaccessible", LAST_PID_PATH);
	return -1;
}

static int check_sock_peek_off(void)
{
	int sk;
	int ret, off, sz;

	sk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create unix socket for check");
		return -1;
	}

	sz = sizeof(off);
	ret = getsockopt(sk, SOL_SOCKET, SO_PEEK_OFF, &off, (socklen_t *)&sz);
	close(sk);

	if ((ret == 0) && (off == -1) && (sz == sizeof(int)))
		return 0;

	pr_msg("SO_PEEK_OFF sockoption doesn't work.\n");
	return -1;
}

static int check_kcmp(void)
{
	int ret = syscall(SYS_kcmp, getpid(), -1, -1, -1, -1);

	if (ret < 0 && errno == ENOSYS) {
		pr_perror("System call kcmp is not supported");
		return -1;
	}

	return 0;
}

static int check_prctl_cat1(void)
{
	unsigned long user_auxv = 0;
	unsigned int *tid_addr;
	unsigned int size = 0;
	int ret;

	ret = prctl(PR_GET_TID_ADDRESS, (unsigned long)&tid_addr, 0, 0, 0);
	if (ret < 0) {
		pr_msg("prctl: PR_GET_TID_ADDRESS is not supported: %m");
		return -1;
	}

	/*
	 * It's OK if the new interface is not supported because it's
	 * a Category 2 feature, but the old interface has to be supported.
	 */
	ret = prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&size, 0, 0);
	if (ret < 0) {
		pr_msg("Info  prctl: PR_SET_MM_MAP_SIZE is not supported\n");
		ret = prctl(PR_SET_MM, PR_SET_MM_BRK, (unsigned long)sbrk(0), 0, 0);
		if (ret < 0) {
			if (errno == EPERM)
				pr_msg("prctl: One needs CAP_SYS_RESOURCE capability to perform testing\n");
			else
				pr_msg("prctl: PR_SET_MM_BRK is not supported: %m\n");
			return -1;
		}

		ret = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, -1, 0, 0);
		if (ret < 0 && errno != EBADF) {
			pr_msg("prctl: PR_SET_MM_EXE_FILE is not supported: %m\n");
			return -1;
		}

		ret = prctl(PR_SET_MM, PR_SET_MM_AUXV, (long)&user_auxv, sizeof(user_auxv), 0);
		if (ret < 0) {
			pr_msg("prctl: PR_SET_MM_AUXV is not supported: %m\n");
			return -1;
		}
	}

	return 0;
}

static int check_prctl_cat2(void)
{
	unsigned int size = 0;
	int ret;

	ret = prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&size, 0, 0);
	if (ret) {
		pr_warn("prctl: PR_SET_MM_MAP_SIZE is not supported\n");
		return -1;
	}
	return 0;
}

static int check_fcntl(void)
{
	u32 v[2];
	int fd;

	fd = open_proc(PROC_SELF, "comm");
	if (fd < 0)
		return -1;

	if (fcntl(fd, F_GETOWNER_UIDS, (long)v)) {
		pr_perror("Can'r fetch file owner UIDs");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int check_proc_stat(void)
{
	struct proc_pid_stat stat;
	int ret;

	ret = parse_pid_stat(getpid(), &stat);
	if (ret) {
		pr_msg("procfs: stat extension is not supported\n");
		return -1;
	}

	return 0;
}

static int check_fdinfo_eventfd(void)
{
	int fd, ret;
	int cnt = 13;
	EventfdFileEntry fe = EVENTFD_FILE_ENTRY__INIT;

	fd = eventfd(cnt, 0);
	if (fd < 0) {
		pr_perror("Can't make eventfd");
		return -1;
	}

	ret = parse_fdinfo(fd, FD_TYPES__EVENTFD, &fe);
	close(fd);

	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	if (fe.counter != cnt) {
		pr_err("Counter mismatch (or not met) %d want %d\n",
				(int)fe.counter, cnt);
		return -1;
	}

	pr_info("Eventfd fdinfo works OK (%d vs %d)\n", cnt, (int)fe.counter);
	return 0;
}

int check_mnt_id(void)
{
	struct fdinfo_common fdinfo = { .mnt_id = -1 };
	int ret;

	ret = parse_fdinfo(get_service_fd(LOG_FD_OFF), FD_TYPES__UND, &fdinfo);
	if (ret < 0)
		return -1;

	if (fdinfo.mnt_id == -1) {
		pr_err("fdinfo doesn't contain the mnt_id field\n");
		return -1;
	}

	return 0;
}

static int check_fdinfo_signalfd(void)
{
	int fd, ret;
	sigset_t mask;
	SignalfdEntry sfd = SIGNALFD_ENTRY__INIT;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		pr_perror("Can't make signalfd");
		return -1;
	}

	ret = parse_fdinfo(fd, FD_TYPES__SIGNALFD, &sfd);
	close(fd);

	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	return 0;
}

static int check_fdinfo_eventpoll(void)
{
	int efd, pfd[2], ret = -1;
	struct epoll_event ev;
	EventpollFileEntry efe = EVENTPOLL_FILE_ENTRY__INIT;

	if (pipe(pfd)) {
		pr_perror("Can't make pipe to watch");
		return -1;
	}

	efd = epoll_create(1);
	if (efd < 0) {
		pr_perror("Can't make epoll fd");
		goto pipe_err;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;

	if (epoll_ctl(efd, EPOLL_CTL_ADD, pfd[0], &ev)) {
		pr_perror("Can't add epoll tfd");
		goto epoll_err;
	}

	ret = parse_fdinfo(efd, FD_TYPES__EVENTPOLL, &efe);
	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		goto epoll_err;
	}

	if (efe.n_tfd != 1 || efe.tfd[0]->tfd != pfd[0]) {
		pr_err("TFD mismatch (or not met)\n");
		ret = -1;
		goto epoll_err;
	}

	pr_info("Epoll fdinfo works OK\n");

epoll_err:
	close(efd);
pipe_err:
	close(pfd[0]);
	close(pfd[1]);

	return ret;
}

static int check_fdinfo_inotify(void)
{
	int ifd, wd, ret;
	InotifyFileEntry ify = INOTIFY_FILE_ENTRY__INIT;

	ifd = inotify_init1(0);
	if (ifd < 0) {
		pr_perror("Can't make inotify fd");
		return -1;
	}

	wd = inotify_add_watch(ifd, ".", IN_ALL_EVENTS);
	if (wd < 0) {
		pr_perror("Can't add watch");
		close(ifd);
		return -1;
	}

	ret = parse_fdinfo(ifd, FD_TYPES__INOTIFY, &ify);
	close(ifd);

	if (ret < 0) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	if (ify.n_wd != 1 || ify.wd[0]->wd != wd) {
		pr_err("WD mismatch (or not met)\n");
		return -1;
	}

	pr_info("Inotify fdinfo works OK\n");
	return 0;
}

static int check_fdinfo_ext(void)
{
	int ret = 0;

	ret |= check_fdinfo_eventfd();
	ret |= check_fdinfo_eventpoll();
	ret |= check_fdinfo_signalfd();
	ret |= check_fdinfo_inotify();

	return ret;
}

static int check_unaligned_vmsplice(void)
{
	int p[2], ret;
	char buf; /* :) */
	struct iovec iov;

	ret = pipe(p);
	if (ret < 0) {
		pr_perror("Can't create pipe");
		return ret;
	}
	iov.iov_base = &buf;
	iov.iov_len = sizeof(buf);
	ret = vmsplice(p[1], &iov, 1, SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
	if (ret < 0) {
		pr_perror("Unaligned vmsplice doesn't work");
		goto err;
	}

	pr_info("Unaligned vmsplice works OK\n");
	ret = 0;
err:
	close(p[0]);
	close(p[1]);

	return ret;
}

#ifndef SO_GET_FILTER
#define SO_GET_FILTER           SO_ATTACH_FILTER
#endif

static int check_so_gets(void)
{
	int sk, ret = -1;
	socklen_t len;
	char name[IFNAMSIZ];

	sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0) {
		pr_perror("No socket");
		return -1;
	}

	len = 0;
	if (getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, NULL, &len)) {
		pr_perror("Can't get socket filter");
		goto err;
	}

	len = sizeof(name);
	if (getsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, name, &len)) {
		pr_perror("Can't get socket bound dev");
		goto err;
	}

	ret = 0;
err:
	close(sk);
	return ret;
}

static int check_ipc(void)
{
	int ret;

	ret = access("/proc/sys/kernel/sem_next_id", R_OK | W_OK);
	if (!ret)
		return 0;

	pr_perror("/proc/sys/kernel/sem_next_id is inaccessible");
	return -1;
}

static int check_sigqueuinfo()
{
	siginfo_t info = { .si_code = 1 };

	signal(SIGUSR1, SIG_IGN);

	if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, &info) < 0) {
		pr_perror("Unable to send siginfo with positive si_code to itself");
		return -1;
	}

	return 0;
}

static pid_t fork_and_ptrace_attach(int (*child_setup)(void))
{
	pid_t pid;
	int sk_pair[2], sk;
	char c = 0;

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		pr_perror("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	} else if (pid == 0) {
		sk = sk_pair[1];
		close(sk_pair[0]);

		if (child_setup && child_setup() != 0)
			exit(1);

		if (write(sk, &c, 1) != 1) {
			pr_perror("write");
			exit(1);
		}

		while (1)
			sleep(1000);
		exit(1);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if (read(sk, &c, 1) != 1) {
		close(sk);
		kill(pid, SIGKILL);
		pr_perror("read");
		return -1;
	}

	close(sk);

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		pr_perror("Unable to ptrace the child");
		kill(pid, SIGKILL);
		return -1;
	}

	waitpid(pid, NULL, 0);

	return pid;
}

static int check_ptrace_peeksiginfo()
{
	struct ptrace_peeksiginfo_args arg;
	siginfo_t siginfo;
	pid_t pid, ret = 0;
	k_rtsigset_t mask;

	pid = fork_and_ptrace_attach(NULL);
	if (pid < 0)
		return -1;

	arg.flags = 0;
	arg.off = 0;
	arg.nr = 1;

	if (ptrace(PTRACE_PEEKSIGINFO, pid, &arg, &siginfo) != 0) {
		pr_perror("Unable to dump pending signals");
		ret = -1;
	}

	if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(mask), &mask) != 0) {
		pr_perror("Unable to dump signal blocking mask");
		ret = -1;
	}

	kill(pid, SIGKILL);
	return ret;
}

static int check_ptrace_suspend_seccomp(void)
{
	pid_t pid;
	int ret = 0;

	pid = fork_and_ptrace_attach(NULL);
	if (pid < 0)
		return -1;

	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_SUSPEND_SECCOMP) < 0) {
		if (errno == EINVAL) {
			pr_err("Kernel doesn't support PTRACE_O_SUSPEND_SECCOMP\n");
		} else {
			pr_perror("couldn't suspend seccomp");
		}
		ret = -1;
	}

	kill(pid, SIGKILL);
	return ret;
}

static int setup_seccomp_filter(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		/* Allow all syscalls except ptrace */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog bpf_prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long) &bpf_prog, 0, 0) < 0)
		return -1;

	return 0;
}

static int check_ptrace_dump_seccomp_filters(void)
{
	pid_t pid;
	int ret = 0, len;

	pid = fork_and_ptrace_attach(setup_seccomp_filter);
	if (pid < 0)
		return -1;

	len = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, NULL);
	if (len < 0) {
		ret = -1;
		pr_perror("Dumping seccomp filters not supported");
	}

	kill(pid, SIGKILL);
	return ret;
}

static int check_mem_dirty_track(void)
{
	if (!kdat.has_dirty_track) {
		pr_warn("Dirty tracking is OFF. Memory snapshot will not work.\n");
		return -1;
	}
	return 0;
}

static int check_posix_timers(void)
{
	int ret;

	ret = access("/proc/self/timers", R_OK);
	if (!ret)
		return 0;

	pr_msg("/proc/<pid>/timers file is missing.\n");
	return -1;
}

static unsigned long get_ring_len(unsigned long addr)
{
	FILE *maps;
	char buf[256];

	maps = fopen_proc(PROC_SELF, "maps");
	if (!maps)
		return 0;

	while (fgets(buf, sizeof(buf), maps)) {
		unsigned long start, end;
		int r, tail;

		r = sscanf(buf, "%lx-%lx %*s %*s %*s %*s %n\n", &start, &end, &tail);
		if (r != 2) {
			fclose(maps);
			pr_err("Bad maps format %d.%d (%s)\n", r, tail, buf + tail);
			return 0;
		}

		if (start == addr) {
			fclose(maps);
			if (strcmp(buf + tail, "/[aio] (deleted)\n"))
				goto notfound;

			return end - start;
		}
	}

	fclose(maps);
notfound:
	pr_err("No AIO ring at expected location\n");
	return 0;
}

static int check_aio_remap(void)
{
	aio_context_t ctx = 0;
	unsigned long len;
	void *naddr;
	int r;

	if (syscall(SYS_io_setup, 16, &ctx) < 0) {
		pr_err("No AIO syscall: %m\n");
		return -1;
	}

	len = get_ring_len((unsigned long) ctx);
	if (!len)
		return -1;

	naddr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
	if (naddr == MAP_FAILED) {
		pr_perror("Can't find place for new AIO ring");
		return -1;
	}

	if (mremap((void *)ctx, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, naddr) == MAP_FAILED) {
		pr_perror("Can't remap AIO ring");
		return -1;
	}

	ctx = (aio_context_t)naddr;
	r = syscall(SYS_io_getevents, ctx, 0, 1, NULL, NULL);
	if (r < 0) {
		pr_err("AIO remap doesn't work properly: %m\n");
		return -1;
	}

	return 0;
}

static int check_fdinfo_lock(void)
{
	if (!kdat.has_fdinfo_lock) {
		pr_err("fdinfo doesn't contain the lock field\n");
		return -1;
	}

	return 0;
}

struct clone_arg {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[128] __stack_aligned__;
	char stack_ptr[0];
};

static int clone_cb(void *_arg) {
	exit(0);
}

static int check_clone_parent_vs_pid()
{
	struct clone_arg ca;
	pid_t pid;

	pid = clone(clone_cb, ca.stack_ptr, CLONE_NEWPID | CLONE_PARENT, &ca);
	if (pid < 0) {
		pr_err("CLONE_PARENT | CLONE_NEWPID don't work together\n");
		return -1;
	}

	return 0;
}

static int check_autofs_pipe_ino(void)
{
	FILE *f;
	char str[1024];
	int ret = -ENOENT;

	f = fopen_proc(PROC_SELF, "mountinfo");
	if (!f)
		return -1;

	while (fgets(str, sizeof(str), f)) {
		if (strstr(str, " autofs ")) {
			if (strstr(str, "pipe_ino="))
				ret = 0;
			else {
				pr_err("autofs not supported.\n");
				ret = -ENOTSUP;
			}
			break;
		}
	}

	fclose(f);
	return ret;
}

static int check_autofs(void)
{
	char *dir, *options, template[] = "/tmp/.criu.mnt.XXXXXX";
	int ret, pfd[2];

	ret = check_autofs_pipe_ino();
	if (ret != -ENOENT)
		return ret;

	if (pipe(pfd) < 0) {
		pr_perror("failed to create pipe");
		return -1;
	}

	ret = -1;

	options = xsprintf("fd=%d,pgrp=%d,minproto=5,maxproto=5,direct",
				pfd[1], getpgrp());
	if (!options) {
		pr_err("failed to allocate autofs options\n");
		goto close_pipe;
	}

	dir = mkdtemp(template);
	if (!dir) {
		pr_perror("failed to construct temporary name");
		goto free_options;
	}

	if (mount("criu", dir, "autofs", 0, options) < 0) {
		pr_perror("failed to mount autofs");
		goto unlink_dir;
	}

	ret = check_autofs_pipe_ino();

	if (umount(dir))
		pr_perror("failed to umount %s", dir);

unlink_dir:
	if (rmdir(dir))
		pr_perror("failed to unlink %s", dir);
free_options:
	free(options);
close_pipe:
	close(pfd[0]);
	close(pfd[1]);
	return ret;
}

static int check_cgroupns(void)
{
	int ret;

	ret = access("/proc/self/ns/cgroup", F_OK);
	if (ret < 0) {
		pr_err("cgroupns not supported. This is not fatal.\n");
		return -1;
	}

	return 0;
}

static int check_tcp(void)
{
	socklen_t optlen;
	int sk, ret;
	int val;

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create TCP socket :(");
		return -1;
	}

	val = 1;
	ret = setsockopt(sk, SOL_TCP, TCP_REPAIR, &val, sizeof(val));
	if (ret < 0) {
		pr_perror("Can't turn TCP repair mode ON");
		goto out;
	}

	optlen = sizeof(val);
	ret = getsockopt(sk, SOL_TCP, TCP_TIMESTAMP, &val, &optlen);
	if (ret)
		pr_perror("Can't get TCP_TIMESTAMP");

out:
	close(sk);

	return ret;
}

static int check_tcp_halt_closed(void)
{
	if (!kdat.has_tcp_half_closed) {
		pr_err("TCP_REPAIR can't be enabled for half-closed sockets\n");
		return -1;
	}

	return 0;
}

static int kerndat_tcp_repair_window(void)
{
	struct tcp_repair_window opt;
	socklen_t optlen = sizeof(opt);
	int sk, val = 1;

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		pr_perror("Unable to create inet socket");
		goto errn;
	}

	if (setsockopt(sk, SOL_TCP, TCP_REPAIR, &val, sizeof(val))) {
		if (errno == EPERM) {
			pr_warn("TCP_REPAIR isn't available to unprivileged users\n");
			goto now;
		}
		pr_perror("Unable to set TCP_REPAIR");
		goto err;
	}

	if (getsockopt(sk, SOL_TCP, TCP_REPAIR_WINDOW, &opt, &optlen)) {
		if (errno != ENOPROTOOPT) {
			pr_perror("Unable to set TCP_REPAIR_WINDOW");
			goto err;
		}
now:
		val = 0;
	} else
		val = 1;

	close(sk);
	return val;

err:
	close(sk);
errn:
	return -1;
}

static int check_tcp_window(void)
{
	int ret;

	ret = kerndat_tcp_repair_window();
	if (ret < 0)
		return -1;

	if (ret == 0) {
		pr_err("The TCP_REPAIR_WINDOW option isn't supported.\n");
		return -1;
	}

	return 0;
}

static int check_userns(void)
{
	int ret;
	unsigned long size = 0;

	ret = access("/proc/self/ns/user", F_OK);
	if (ret) {
		pr_perror("No userns proc file");
		return -1;
	}

	ret = prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&size, 0, 0);
	if (ret < 0) {
		pr_perror("prctl: PR_SET_MM_MAP_SIZE is not supported");
		return -1;
	}

	return 0;
}

static int check_loginuid(void)
{
	if (kdat.luid != LUID_FULL) {
		pr_warn("Loginuid restore is OFF.\n");
		return -1;
	}

	return 0;
}

static int check_compat_cr(void)
{
#ifdef CONFIG_COMPAT
	if (kdat_compatible_cr())
		return 0;
	pr_warn("compat_cr is not supported. Requires kernel >= v4.12\n");
#else
	pr_warn("CRIU built without CONFIG_COMPAT - can't C/R ia32\n");
#endif
	return -1;
}

static int check_uffd(void)
{
	if (!kdat.has_uffd) {
		pr_err("UFFD is not supported\n");
		return -1;
	}

	return 0;
}

static int check_uffd_noncoop(void)
{
	if (check_uffd())
		return -1;

	if (!uffd_noncooperative()) {
		pr_err("Non-cooperative UFFD is not supported\n");
		return -1;
	}

	return 0;
}

static int check_can_map_vdso(void)
{
	if (kdat_can_map_vdso() == 1)
		return 0;
	pr_warn("Do not have API to map vDSO - will use mremap() to restore vDSO\n");
	return -1;
}

static int (*chk_feature)(void);

/*
 * There are three categories of kernel features:
 *
 * 1. Absolutely required (/proc/pid/map_files, ptrace PEEKSIGINFO, etc.).
 * 2. Required only for specific cases (aio remap, tun, etc.).
 *    Checked when --extra or --all is specified.
 * 3. Experimental (task-diag).
 *    Checked when --experimental or --all is specified.
 *
 * We fail if any feature in category 1 is missing but tolerate failures
 * in the other categories.  Currently, there is nothing in category 3.
 */
#define CHECK_GOOD	"Looks good."
#define CHECK_BAD	"Does not look good."
#define CHECK_MAYBE	"Looks good but some kernel features are missing\n" \
			"which, depending on your process tree, may cause\n" \
			"dump or restore failure."
#define CHECK_CAT1(fn)	do { \
				if ((ret = fn) != 0) { \
					print_on_level(DEFAULT_LOGLEVEL, "%s\n", CHECK_BAD); \
					return ret; \
				} \
			} while (0)
int cr_check(void)
{
	struct ns_id *ns;
	int ret = 0;

	if (!is_root_user())
		return -1;

	root_item = alloc_pstree_item();
	if (root_item == NULL)
		return -1;

	root_item->pid->real = getpid();

	if (collect_pstree_ids())
		return -1;

	ns = lookup_ns_by_id(root_item->ids->mnt_ns_id, &mnt_ns_desc);
	if (ns == NULL)
		return -1;

	mntinfo = collect_mntinfo(ns, false);
	if (mntinfo == NULL)
		return -1;

	if (chk_feature) {
		if (chk_feature())
			return -1;
		print_on_level(DEFAULT_LOGLEVEL, "%s is supported\n",
			feature_name(chk_feature));
		return 0;
	}

	/*
	 * Category 1 - absolutely required.
	 * So that the user can see clearly what's missing, we exit with
	 * non-zero status on the first failure because it gets very
	 * confusing when there are many warnings and error messages.
	 */
	CHECK_CAT1(check_map_files());
	CHECK_CAT1(check_sock_diag());
	CHECK_CAT1(check_ns_last_pid());
	CHECK_CAT1(check_sock_peek_off());
	CHECK_CAT1(check_kcmp());
	CHECK_CAT1(check_prctl_cat1());
	CHECK_CAT1(check_fcntl());
	CHECK_CAT1(check_proc_stat());
	CHECK_CAT1(check_tcp());
	CHECK_CAT1(check_fdinfo_ext());
	CHECK_CAT1(check_unaligned_vmsplice());
	CHECK_CAT1(check_tty());
	CHECK_CAT1(check_so_gets());
	CHECK_CAT1(check_ipc());
	CHECK_CAT1(check_sigqueuinfo());
	CHECK_CAT1(check_ptrace_peeksiginfo());

	/*
	 * Category 2 - required for specific cases.
	 * Unlike Category 1 features, we don't exit with non-zero status
	 * on a failure because CRIU may still work.
	 */
	if (opts.check_extra_features) {
		ret |= check_prctl_cat2();
		ret |= check_ptrace_suspend_seccomp();
		ret |= check_ptrace_dump_seccomp_filters();
		ret |= check_mem_dirty_track();
		ret |= check_posix_timers();
		ret |= check_tun_cr(0);
		ret |= check_timerfd();
		ret |= check_mnt_id();
		ret |= check_aio_remap();
		ret |= check_fdinfo_lock();
		ret |= check_clone_parent_vs_pid();
		ret |= check_cgroupns();
		ret |= check_tcp_window();
		ret |= check_tcp_halt_closed();
		ret |= check_userns();
		ret |= check_loginuid();
		ret |= check_can_map_vdso();
	}

	/*
	 * Category 3 - experimental.
	 */
	if (opts.check_experimental_features) {
		ret |= check_autofs();
		ret |= check_compat_cr();
	}

	print_on_level(DEFAULT_LOGLEVEL, "%s\n", ret ? CHECK_MAYBE : CHECK_GOOD);
	return ret;
}
#undef CHECK_GOOD
#undef CHECK_BAD
#undef CHECK_MAYBE
#undef CHECK_CAT1

static int check_tun(void)
{
	/*
	 * In case there's no TUN support at all we
	 * should report error. Unlike this plain criu
	 * check would report "Looks good" in this case
	 * since C/R effectively works, just not for TUN.
	 */
	return check_tun_cr(-1);
}

struct feature_list {
	char *name;
	int (*func)();
};

static struct feature_list feature_list[] = {
	{ "mnt_id", check_mnt_id },
	{ "mem_dirty_track", check_mem_dirty_track },
	{ "aio_remap", check_aio_remap },
	{ "timerfd", check_timerfd },
	{ "tun", check_tun },
	{ "userns", check_userns },
	{ "fdinfo_lock", check_fdinfo_lock },
	{ "seccomp_suspend", check_ptrace_suspend_seccomp },
	{ "seccomp_filters", check_ptrace_dump_seccomp_filters },
	{ "loginuid", check_loginuid },
	{ "cgroupns", check_cgroupns },
	{ "autofs", check_autofs },
	{ "tcp_half_closed", check_tcp_halt_closed },
	{ "compat_cr", check_compat_cr },
	{ "uffd", check_uffd },
	{ "uffd-noncoop", check_uffd_noncoop },
	{ "can_map_vdso", check_can_map_vdso},
	{ NULL, NULL },
};

void pr_check_features(const char *offset, const char *sep, int width)
{
	struct feature_list *fl;
	int pos = width + 1;
	int sep_len = strlen(sep);
	int offset_len = strlen(offset);

	for (fl = feature_list; fl->name; fl++) {
		int len = strlen(fl->name);

		if (pos + len + sep_len > width) {
			pr_msg("\n%s", offset);
			pos = offset_len;
		}
		pr_msg("%s", fl->name);
		pos += len;
		if ((fl + 1)->name) { // not the last item
			pr_msg("%s", sep);
			pos += sep_len;
		}
	}
	pr_msg("\n");
}

int check_add_feature(char *feat)
{
	struct feature_list *fl;

	for (fl = feature_list; fl->name; fl++) {
		if (!strcmp(feat, fl->name)) {
			chk_feature = fl->func;
			return 0;
		}
	}
	pr_err("Unknown feature %s\n", feat);
	return -1;
}

static char *feature_name(int (*func)())
{
	struct feature_list *fl;

	for (fl = feature_list; fl->func; fl++) {
		if (fl->func == func)
			return fl->name;
	}
	return NULL;
}
