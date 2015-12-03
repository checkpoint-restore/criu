#include <unistd.h>
#include <linux/netlink.h>
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

#include "proc_parse.h"
#include "sockets.h"
#include "crtools.h"
#include "log.h"
#include "util-pie.h"
#include "syscall.h"
#include "prctl.h"
#include "files.h"
#include "sk-inet.h"
#include "proc_parse.h"
#include "mount.h"
#include "tty.h"
#include "ptrace.h"
#include "kerndat.h"
#include "timerfd.h"
#include "tun.h"
#include "namespaces.h"
#include "pstree.h"
#include "cr_options.h"

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
	int ret = sys_kcmp(getpid(), -1, -1, -1, -1);

	if (ret != -ENOSYS)
		return 0;

	errno = -ret;
	pr_perror("System call kcmp is not supported");
	return -1;
}

static int check_prctl(void)
{
	unsigned long user_auxv = 0;
	unsigned int *tid_addr;
	unsigned int size = 0;
	int ret;

	ret = sys_prctl(PR_GET_TID_ADDRESS, (unsigned long)&tid_addr, 0, 0, 0);
	if (ret) {
		pr_msg("prctl: PR_GET_TID_ADDRESS is not supported");
		return -1;
	}

	/*
	 * Either new or old interface must be supported in the kernel.
	 */
	ret = sys_prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&size, 0, 0);
	if (ret) {
		if (!opts.check_ms_kernel) {
			pr_msg("prctl: PR_SET_MM_MAP is not supported, which "
			       "is required for restoring user namespaces\n");
			return -1;
		} else
			pr_warn("Skipping unssuported PR_SET_MM_MAP\n");

		ret = sys_prctl(PR_SET_MM, PR_SET_MM_BRK, sys_brk(0), 0, 0);
		if (ret) {
			if (ret == -EPERM)
				pr_msg("prctl: One needs CAP_SYS_RESOURCE capability to perform testing\n");
			else
				pr_msg("prctl: PR_SET_MM is not supported\n");
			return -1;
		}

		ret = sys_prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, -1, 0, 0);
		if (ret != -EBADF) {
			pr_msg("prctl: PR_SET_MM_EXE_FILE is not supported (%d)\n", ret);
			return -1;
		}

		ret = sys_prctl(PR_SET_MM, PR_SET_MM_AUXV, (long)&user_auxv, sizeof(user_auxv), 0);
		if (ret) {
			pr_msg("prctl: PR_SET_MM_AUXV is not supported\n");
			return -1;
		}
	}

	return 0;
}

static int check_fcntl(void)
{
	u32 v[2];
	int fd;

	fd = open("/proc/self/comm", O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open self comm file");
		return -1;
	}

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

static int check_one_fdinfo(union fdinfo_entries *e, void *arg)
{
	*(int *)arg = (int)e->efd.counter;
	return 0;
}

static int check_fdinfo_eventfd(void)
{
	int fd, ret;
	int cnt = 13, proc_cnt = 0;

	fd = eventfd(cnt, 0);
	if (fd < 0) {
		pr_perror("Can't make eventfd");
		return -1;
	}

	ret = parse_fdinfo(fd, FD_TYPES__EVENTFD, check_one_fdinfo, &proc_cnt);
	close(fd);

	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	if (proc_cnt != cnt) {
		pr_err("Counter mismatch (or not met) %d want %d\n",
				proc_cnt, cnt);
		return -1;
	}

	pr_info("Eventfd fdinfo works OK (%d vs %d)\n", cnt, proc_cnt);
	return 0;
}

static int check_one_sfd(union fdinfo_entries *e, void *arg)
{
	return 0;
}

int check_mnt_id(void)
{
	struct fdinfo_common fdinfo = { .mnt_id = -1 };
	int ret;

	ret = parse_fdinfo(get_service_fd(LOG_FD_OFF), FD_TYPES__UND, NULL, &fdinfo);
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

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		pr_perror("Can't make signalfd");
		return -1;
	}

	ret = parse_fdinfo(fd, FD_TYPES__SIGNALFD, check_one_sfd, NULL);
	close(fd);

	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	return 0;
}

static int check_one_epoll(union fdinfo_entries *e, void *arg)
{
	*(int *)arg = e->epl.e.tfd;
	free_event_poll_entry(e);
	return 0;
}

static int check_fdinfo_eventpoll(void)
{
	int efd, pfd[2], proc_fd = 0, ret = -1;
	struct epoll_event ev;

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

	ret = parse_fdinfo(efd, FD_TYPES__EVENTPOLL, check_one_epoll, &proc_fd);
	if (ret) {
		pr_err("Error parsing proc fdinfo\n");
		goto epoll_err;
	}

	if (pfd[0] != proc_fd) {
		pr_err("TFD mismatch (or not met) %d want %d\n",
				proc_fd, pfd[0]);
		ret = -1;
		goto epoll_err;
	}

	pr_info("Epoll fdinfo works OK (%d vs %d)\n", pfd[0], proc_fd);

epoll_err:
	close(efd);
pipe_err:
	close(pfd[0]);
	close(pfd[1]);

	return ret;
}

static int check_one_inotify(union fdinfo_entries *e, void *arg)
{
	*(int *)arg = e->ify.e.wd;
	free_inotify_wd_entry(e);
	return 0;
}

static int check_fdinfo_inotify(void)
{
	int ifd, wd, proc_wd = -1, ret;

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

	ret = parse_fdinfo(ifd, FD_TYPES__INOTIFY, check_one_inotify, &proc_wd);
	close(ifd);

	if (ret < 0) {
		pr_err("Error parsing proc fdinfo\n");
		return -1;
	}

	if (wd != proc_wd) {
		pr_err("WD mismatch (or not met) %d want %d\n", proc_wd, wd);
		return -1;
	}

	pr_info("Inotify fdinfo works OK (%d vs %d)\n", wd, proc_wd);
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
	int ret;
	siginfo_t info = { .si_code = 1 };

	signal(SIGUSR1, SIG_IGN);

	ret = sys_rt_sigqueueinfo(getpid(), SIGUSR1, &info);
	if (ret < 0) {
		errno = -ret;
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

	if (opts.check_ms_kernel) {
		pr_warn("Skipping PTRACE_O_SUSPEND_SECCOMP check\n");
		return 0;
	}

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

	if (sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long) &bpf_prog, 0, 0) < 0)
		return -1;

	return 0;
}

static int check_ptrace_dump_seccomp_filters(void)
{
	pid_t pid;
	int ret = 0, len;

	if (opts.check_ms_kernel) {
		pr_warn("Skipping PTRACE_SECCOMP_GET_FILTER check");
		return 0;
	}

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
	if (kerndat_get_dirty_track() < 0)
		return -1;

	if (!kdat.has_dirty_track)
		pr_warn("Dirty tracking is OFF. Memory snapshot will not work.\n");
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

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		pr_perror("No maps proc file");
		return 0;
	}

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

	if (sys_io_setup(16, &ctx) < 0) {
		pr_err("No AIO syscall\n");
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
	r = sys_io_getevents(ctx, 0, 1, NULL, NULL);
	if (r < 0) {
		if (!opts.check_ms_kernel) {
			pr_err("AIO remap doesn't work properly\n");
			return -1;
		} else
			pr_warn("Skipping unsupported AIO remap\n");
	}

	return 0;
}

static int check_fdinfo_lock(void)
{
	if (kerndat_fdinfo_has_lock())
		return -1;

	if (!kdat.has_fdinfo_lock) {
		if (!opts.check_ms_kernel) {
			pr_err("fdinfo doesn't contain the lock field\n");
			return -1;
		} else {
			pr_warn("fdinfo doesn't contain the lock field\n");
		}
	}

	return 0;
}

struct clone_arg {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[128] __attribute__((aligned (8)));
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

static int (*chk_feature)(void);

int cr_check(void)
{
	struct ns_id ns = { .type = NS_CRIU, .ns_pid = PROC_SELF, .nd = &mnt_ns_desc };
	int ret = 0;

	if (!is_root_user())
		return -1;

	root_item = alloc_pstree_item();
	if (root_item == NULL)
		return -1;

	root_item->pid.real = getpid();

	if (collect_pstree_ids())
		return -1;

	ns.id = root_item->ids->mnt_ns_id;

	mntinfo = collect_mntinfo(&ns, false);
	if (mntinfo == NULL)
		return -1;

	if (chk_feature) {
		ret = chk_feature();
		goto out;
	}

	ret |= check_map_files();
	ret |= check_sock_diag();
	ret |= check_ns_last_pid();
	ret |= check_sock_peek_off();
	ret |= check_kcmp();
	ret |= check_prctl();
	ret |= check_fcntl();
	ret |= check_proc_stat();
	ret |= check_tcp();
	ret |= check_fdinfo_ext();
	ret |= check_unaligned_vmsplice();
	ret |= check_tty();
	ret |= check_so_gets();
	ret |= check_ipc();
	ret |= check_sigqueuinfo();
	ret |= check_ptrace_peeksiginfo();
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

out:
	if (!ret)
		print_on_level(DEFAULT_LOGLEVEL, "Looks good.\n");

	return ret;
}

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

static int check_userns(void)
{
	int ret;
	unsigned long size = 0;

	ret = access("/proc/self/ns/user", F_OK);
	if (ret) {
		pr_perror("No userns proc file");
		return -1;
	}

	ret = sys_prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&size, 0, 0);
	if (ret) {
		errno = -ret;
		pr_perror("No new prctl API");
		return -1;
	}

	return 0;
}

int check_add_feature(char *feat)
{
	if (!strcmp(feat, "mnt_id"))
		chk_feature = check_mnt_id;
	else if (!strcmp(feat, "aio_remap"))
		chk_feature = check_aio_remap;
	else if (!strcmp(feat, "timerfd"))
		chk_feature = check_timerfd;
	else if (!strcmp(feat, "tun"))
		chk_feature = check_tun;
	else if (!strcmp(feat, "userns"))
		chk_feature = check_userns;
	else if (!strcmp(feat, "fdinfo_lock"))
		chk_feature = check_fdinfo_lock;
	else if (!strcmp(feat, "seccomp_suspend"))
		chk_feature = check_ptrace_suspend_seccomp;
	else if (!strcmp(feat, "seccomp_filters"))
		chk_feature = check_ptrace_dump_seccomp_filters;
	else {
		pr_err("Unknown feature %s\n", feat);
		return -1;
	}

	return 0;
}
