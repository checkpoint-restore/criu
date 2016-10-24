#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include <sys/mount.h>
#include <stdarg.h>
#include <sys/ioctl.h>

#include "int.h"
#include "types.h"
#include "syscall.h"
#include "parasite.h"
#include "config.h"
#include "fcntl.h"
#include "prctl.h"
#include "lock.h"
#include "parasite-vdso.h"
#include "criu-log.h"
#include "tty.h"
#include "aio.h"

#include <string.h>

#include "asm/parasite.h"
#include "restorer.h"

static int tsock = -1;

static struct rt_sigframe *sigframe;

/*
 * PARASITE_CMD_DUMPPAGES is called many times and the parasite args contains
 * an array of VMAs at this time, so VMAs can be unprotected in any moment
 */
static struct parasite_dump_pages_args *mprotect_args = NULL;

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT	0x08
#endif

#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG  2
#endif

static int mprotect_vmas(struct parasite_dump_pages_args *args)
{
	struct parasite_vma_entry *vmas, *vma;
	int ret = 0, i;

	vmas = pargs_vmas(args);
	for (i = 0; i < args->nr_vmas; i++) {
		vma = vmas + i;
		ret = sys_mprotect((void *)vma->start, vma->len, vma->prot | args->add_prot);
		if (ret) {
			pr_err("mprotect(%08lx, %lu) failed with code %d\n",
						vma->start, vma->len, ret);
			break;
		}
	}

	if (args->add_prot)
		mprotect_args = args;
	else
		mprotect_args = NULL;

	return ret;
}

static int dump_pages(struct parasite_dump_pages_args *args)
{
	int p, ret;
	struct iovec *iovs;

	p = recv_fd(tsock);
	if (p < 0)
		return -1;

	iovs = pargs_iovs(args);
	ret = sys_vmsplice(p, &iovs[args->off], args->nr_segs,
				SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
	if (ret != PAGE_SIZE * args->nr_pages) {
		sys_close(p);
		pr_err("Can't splice pages to pipe (%d/%d)\n", ret, args->nr_pages);
		return -1;
	}

	sys_close(p);
	return 0;
}

static int dump_sigact(struct parasite_dump_sa_args *da)
{
	int sig, ret = 0;

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = sys_sigaction(sig, NULL, &da->sas[i], sizeof(k_rtsigset_t));
		if (ret < 0) {
			pr_err("sys_sigaction failed (%d)\n", ret);
			break;
		}
	}

	return ret;
}

static int dump_itimers(struct parasite_dump_itimers_args *args)
{
	int ret;

	ret = sys_getitimer(ITIMER_REAL, &args->real);
	if (!ret)
		ret = sys_getitimer(ITIMER_VIRTUAL, &args->virt);
	if (!ret)
		ret = sys_getitimer(ITIMER_PROF, &args->prof);

	if (ret)
		pr_err("getitimer failed (%d)\n", ret);

	return ret;
}

static int dump_posix_timers(struct parasite_dump_posix_timers_args *args)
{
	int i;
	int ret = 0;

	for(i = 0; i < args->timer_n; i++) {
		ret = sys_timer_gettime(args->timer[i].it_id, &args->timer[i].val);
		if (ret < 0) {
			pr_err("sys_timer_gettime failed (%d)\n", ret);
			return ret;
		}
		args->timer[i].overrun = sys_timer_getoverrun(args->timer[i].it_id);
		ret = args->timer[i].overrun;
		if (ret < 0) {
			pr_err("sys_timer_getoverrun failed (%d)\n", ret);
			return ret;
		}
	}

	return ret;
}

static int dump_creds(struct parasite_dump_creds *args);

static int dump_thread_common(struct parasite_dump_thread *ti)
{
	int ret;

	arch_get_tls(&ti->tls);
	ret = sys_prctl(PR_GET_TID_ADDRESS, (unsigned long) &ti->tid_addr, 0, 0, 0);
	if (ret)
		goto out;

	ret = sys_sigaltstack(NULL, &ti->sas);
	if (ret)
		goto out;

	ret = sys_prctl(PR_GET_PDEATHSIG, (unsigned long)&ti->pdeath_sig, 0, 0, 0);
	if (ret)
		goto out;

	ret = dump_creds(ti->creds);
out:
	return ret;
}

static int dump_misc(struct parasite_dump_misc *args)
{
	args->brk = sys_brk(0);

	args->pid = sys_getpid();
	args->sid = sys_getsid();
	args->pgid = sys_getpgid(0);
	args->umask = sys_umask(0);
	sys_umask(args->umask); /* never fails */
	args->dumpable = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);

	return 0;
}

static int dump_creds(struct parasite_dump_creds *args)
{
	int ret, i, j;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];
	struct cap_header hdr = {_LINUX_CAPABILITY_VERSION_3, 0};

	ret = sys_capget(&hdr, data);
	if (ret < 0) {
		pr_err("Unable to get capabilities: %d\n", ret);
		return -1;
	}

	/*
	 * Loop through the capability constants until we reach cap_last_cap.
	 * The cap_bnd set is stored as a bitmask comprised of CR_CAP_SIZE number of
	 * 32-bit uints, hence the inner loop from 0 to 32.
	 */
	for (i = 0; i < CR_CAP_SIZE; i++) {
		args->cap_eff[i] = data[i].eff;
		args->cap_prm[i] = data[i].prm;
		args->cap_inh[i] = data[i].inh;
		args->cap_bnd[i] = 0;

		for (j = 0; j < 32; j++) {
			if (j + i * 32 > args->cap_last_cap)
				break;
			ret = sys_prctl(PR_CAPBSET_READ, j + i * 32, 0, 0, 0);
			if (ret < 0) {
				pr_err("Unable to read capability %d: %d\n",
					j + i * 32, ret);
				return -1;
			}
			if (ret)
				args->cap_bnd[i] |= (1 << j);
		}
	}

	args->secbits = sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);

	ret = sys_getgroups(0, NULL);
	if (ret < 0)
		goto grps_err;

	args->ngroups = ret;
	if (args->ngroups >= PARASITE_MAX_GROUPS) {
		pr_err("Too many groups in task %d\n", (int)args->ngroups);
		return -1;
	}

	ret = sys_getgroups(args->ngroups, args->groups);
	if (ret < 0)
		goto grps_err;

	if (ret != args->ngroups) {
		pr_err("Groups changed on the fly %d -> %d\n",
				args->ngroups, ret);
		return -1;
	}

	ret = sys_getresuid(&args->uids[0], &args->uids[1], &args->uids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->uids[3] = sys_setfsuid(-1L);

	/*
	 * FIXME In https://github.com/xemul/criu/issues/95 it is
	 * been reported that only low 16 bits are set upon syscall
	 * on ARMv7.
	 *
	 * We may rather need implement builtin-memset and clear the
	 * whole memory needed here.
	 */
	args->gids[0] = args->gids[1] = args->gids[2] = args->gids[3] = 0;

	ret = sys_getresgid(&args->gids[0], &args->gids[1], &args->gids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->gids[3] = sys_setfsgid(-1L);

	return 0;

grps_err:
	pr_err("Error calling getgroups (%d)\n", ret);
	return -1;
}

static int drain_fds(struct parasite_drain_fd *args)
{
	int ret;

	ret = send_fds(tsock, NULL, 0,
		       args->fds, args->nr_fds, true);
	if (ret)
		pr_err("send_fds failed (%d)\n", ret);

	return ret;
}

static int dump_thread(struct parasite_dump_thread *args)
{
	args->tid = sys_gettid();
	return dump_thread_common(args);
}

static char proc_mountpoint[] = "proc.crtools";

static int pie_atoi(char *str)
{
	int ret = 0;

	while (*str) {
		ret *= 10;
		ret += *str - '0';
		str++;
	}

	return ret;
}

static int get_proc_fd(void)
{
	int ret;
	char buf[11];

	ret = sys_readlinkat(AT_FDCWD, "/proc/self", buf, sizeof(buf) - 1);
	if (ret < 0 && ret != -ENOENT) {
		pr_err("Can't readlink /proc/self (%d)\n", ret);
		return ret;
	}
	if (ret > 0) {
		buf[ret] = 0;

		/* Fast path -- if /proc belongs to this pidns */
		if (pie_atoi(buf) == sys_getpid())
			return sys_open("/proc", O_RDONLY, 0);
	}

	ret = sys_mkdir(proc_mountpoint, 0700);
	if (ret) {
		pr_err("Can't create a directory (%d)\n", ret);
		return -1;
	}

	ret = sys_mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL);
	if (ret) {
		if (ret == -EPERM)
			pr_err("can't dump unpriviliged task whose /proc doesn't belong to it\n");
		else
			pr_err("mount failed (%d)\n", ret);
		sys_rmdir(proc_mountpoint);
		return -1;
	}

	return open_detach_mount(proc_mountpoint);
}

static int parasite_get_proc_fd(void)
{
	int fd, ret;

	fd = get_proc_fd();
	if (fd < 0) {
		pr_err("Can't get /proc fd\n");
		return -1;
	}

	ret = send_fd(tsock, NULL, 0, fd);
	sys_close(fd);
	return ret;
}

static inline int tty_ioctl(int fd, int cmd, int *arg)
{
	int ret;

	ret = sys_ioctl(fd, cmd, (unsigned long)arg);
	if (ret < 0) {
		if (ret != -ENOTTY)
			return ret;
		*arg = 0;
	}
	return 0;
}

/*
 * Stolen from kernel/fs/aio.c
 *
 * Is it valid to go to memory and check it? Should be,
 * as libaio does the same.
 */

#define AIO_RING_MAGIC			0xa10a10a1
#define AIO_RING_COMPAT_FEATURES	1
#define AIO_RING_INCOMPAT_FEATURES	0

static int sane_ring(struct parasite_aio *aio)
{
	struct aio_ring *ring = (struct aio_ring *)aio->ctx;
	unsigned nr;

	nr = (aio->size - sizeof(struct aio_ring)) / sizeof(struct io_event);

	return ring->magic == AIO_RING_MAGIC &&
		ring->compat_features == AIO_RING_COMPAT_FEATURES &&
		ring->incompat_features == AIO_RING_INCOMPAT_FEATURES &&
		ring->header_length == sizeof(struct aio_ring) &&
		ring->nr == nr;
}

static int parasite_check_aios(struct parasite_check_aios_args *args)
{
	int i;

	for (i = 0; i < args->nr_rings; i++) {
		struct aio_ring *ring;

		ring = (struct aio_ring *)args->ring[i].ctx;
		if (!sane_ring(&args->ring[i])) {
			pr_err("Not valid ring #%d\n", i);
			pr_info(" `- magic %x\n", ring->magic);
			pr_info(" `- cf    %d\n", ring->compat_features);
			pr_info(" `- if    %d\n", ring->incompat_features);
			pr_info(" `- header size  %d (%zd)\n", ring->header_length, sizeof(struct aio_ring));
			pr_info(" `- nr    %d\n", ring->nr);
			return -1;
		}

		/* XXX: wait aio completion */
	}

	return 0;
}

static int parasite_dump_tty(struct parasite_tty_args *args)
{
	int ret;

#ifndef TIOCGPKT
# define TIOCGPKT	_IOR('T', 0x38, int)
#endif

#ifndef TIOCGPTLCK
# define TIOCGPTLCK	_IOR('T', 0x39, int)
#endif

#ifndef TIOCGEXCL
# define TIOCGEXCL	_IOR('T', 0x40, int)
#endif

	args->sid = 0;
	args->pgrp = 0;
	args->st_pckt = 0;
	args->st_lock = 0;
	args->st_excl = 0;

#define __tty_ioctl(cmd, arg)					\
	do {							\
		ret = tty_ioctl(args->fd, cmd, &arg);		\
		if (ret < 0) {					\
			if (ret == -ENOTTY)			\
				arg = 0;			\
			else if (ret == -EIO)			\
				goto err_io;			\
			else					\
				goto err;			\
		}						\
	} while (0)

	__tty_ioctl(TIOCGSID, args->sid);
	__tty_ioctl(TIOCGPGRP, args->pgrp);
	__tty_ioctl(TIOCGEXCL,	args->st_excl);

	if (args->type == TTY_TYPE__PTY) {
		__tty_ioctl(TIOCGPKT,	args->st_pckt);
		__tty_ioctl(TIOCGPTLCK,	args->st_lock);
	}

	args->hangup = false;
	return 0;

err:
	pr_err("tty: Can't fetch params: err = %d\n", ret);
	return -1;
err_io:

	/* kernel reports EIO for get ioctls on pair-less ptys */
	pr_debug("tty: EIO on tty\n");
	args->hangup = true;
	return 0;
#undef __tty_ioctl
}

#ifdef CONFIG_VDSO
static int parasite_check_vdso_mark(struct parasite_vdso_vma_entry *args)
{
	struct vdso_mark *m = (void *)args->start;

	if (is_vdso_mark(m)) {
		/*
		 * Make sure we don't meet some corrupted entry
		 * where signature matches but verions is not!
		 */
		if (m->version != VDSO_MARK_CUR_VERSION) {
			pr_err("vdso: Mark version mismatch!\n");
			return -EINVAL;
		}
		args->is_marked = 1;
		args->proxy_vdso_addr = m->proxy_vdso_addr;
		args->proxy_vvar_addr = m->proxy_vvar_addr;
	} else {
		args->is_marked = 0;
		args->proxy_vdso_addr = VDSO_BAD_ADDR;
		args->proxy_vvar_addr = VVAR_BAD_ADDR;

		if (args->try_fill_symtable) {
			struct vdso_symtable t;

			if (vdso_fill_symtable(args->start, args->len, &t))
				args->is_vdso = false;
			else
				args->is_vdso = true;
		}
	}

	return 0;
}
#else
static inline int parasite_check_vdso_mark(struct parasite_vdso_vma_entry *args)
{
	pr_err("Unexpected VDSO check command\n");
	return -1;
}
#endif

static int parasite_dump_cgroup(struct parasite_dump_cgroup_args *args)
{
	int proc, cgroup, len;

	proc = get_proc_fd();
	if (proc < 0) {
		pr_err("can't get /proc fd\n");
		return -1;
	}

	cgroup = sys_openat(proc, "self/cgroup", O_RDONLY, 0);
	sys_close(proc);
	if (cgroup < 0) {
		pr_err("can't get /proc/self/cgroup fd\n");
		sys_close(cgroup);
		return -1;
	}

	len = sys_read(cgroup, args->contents, sizeof(args->contents));
	sys_close(cgroup);
	if (len < 0) {
		pr_err("can't read /proc/self/cgroup %d\n", len);
		return -1;
	}

	if (len == sizeof(*args)) {
		pr_warn("/proc/self/cgroup was bigger than the page size\n");
		return -1;
	}

	/* null terminate */
	args->contents[len] = 0;
	return 0;
}

static int __parasite_daemon_reply_ack(unsigned int cmd, int err)
{
	struct ctl_msg m;
	int ret;

	m = ctl_msg_ack(cmd, err);
	ret = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (ret != sizeof(m)) {
		pr_err("Sent only %d bytes while %zu expected\n", ret, sizeof(m));
		return -1;
	}

	pr_debug("__sent ack msg: %d %d %d\n",
		 m.cmd, m.ack, m.err);

	return 0;
}

static int __parasite_daemon_wait_msg(struct ctl_msg *m)
{
	int ret;

	pr_debug("Daemon waits for command\n");

	while (1) {
		*m = (struct ctl_msg){ };
		ret = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (ret != sizeof(*m)) {
			pr_err("Trimmed message received (%d/%d)\n",
			       (int)sizeof(*m), ret);
			return -1;
		}

		pr_debug("__fetched msg: %d %d %d\n",
			 m->cmd, m->ack, m->err);
		return 0;
	}

	return -1;
}

static noinline void fini_sigreturn(unsigned long new_sp)
{
	ARCH_RT_SIGRETURN(new_sp);
}

static int fini(void)
{
	unsigned long new_sp;

	if (mprotect_args) {
		mprotect_args->add_prot = 0;
		mprotect_vmas(mprotect_args);
	}

	new_sp = (long)sigframe + RT_SIGFRAME_OFFSET(sigframe);
	pr_debug("%ld: new_sp=%lx ip %lx\n", sys_gettid(),
		  new_sp, RT_SIGFRAME_REGIP(sigframe));

	sys_close(tsock);
	log_set_fd(-1);

	fini_sigreturn(new_sp);

	BUG();

	return -1;
}

static noinline __used int noinline parasite_daemon(void *args)
{
	struct ctl_msg m;
	int ret = -1;

	pr_debug("Running daemon thread leader\n");

	/* Reply we're alive */
	if (__parasite_daemon_reply_ack(PARASITE_CMD_INIT_DAEMON, 0))
		goto out;

	ret = 0;

	while (1) {
		if (__parasite_daemon_wait_msg(&m))
			break;

		if (ret && m.cmd != PARASITE_CMD_FINI) {
			pr_err("Command rejected\n");
			continue;
		}

		switch (m.cmd) {
		case PARASITE_CMD_FINI:
			goto out;
		case PARASITE_CMD_DUMPPAGES:
			ret = dump_pages(args);
			break;
		case PARASITE_CMD_MPROTECT_VMAS:
			ret = mprotect_vmas(args);
			break;
		case PARASITE_CMD_DUMP_SIGACTS:
			ret = dump_sigact(args);
			break;
		case PARASITE_CMD_DUMP_ITIMERS:
			ret = dump_itimers(args);
			break;
		case PARASITE_CMD_DUMP_POSIX_TIMERS:
			ret = dump_posix_timers(args);
			break;
		case PARASITE_CMD_DUMP_THREAD:
			ret = dump_thread(args);
			break;
		case PARASITE_CMD_DUMP_MISC:
			ret = dump_misc(args);
			break;
		case PARASITE_CMD_DRAIN_FDS:
			ret = drain_fds(args);
			break;
		case PARASITE_CMD_GET_PROC_FD:
			ret = parasite_get_proc_fd();
			break;
		case PARASITE_CMD_DUMP_TTY:
			ret = parasite_dump_tty(args);
			break;
		case PARASITE_CMD_CHECK_AIOS:
			ret = parasite_check_aios(args);
			break;
		case PARASITE_CMD_CHECK_VDSO_MARK:
			ret = parasite_check_vdso_mark(args);
			break;
		case PARASITE_CMD_DUMP_CGROUP:
			ret = parasite_dump_cgroup(args);
			break;
		default:
			pr_err("Unknown command in parasite daemon thread leader: %d\n", m.cmd);
			ret = -1;
			break;
		}

		if (__parasite_daemon_reply_ack(m.cmd, ret))
			break;

		if (ret) {
			pr_err("Close the control socket for writing\n");
			sys_shutdown(tsock, SHUT_WR);
		}
	}

out:
	fini();

	return 0;
}

static noinline int unmap_itself(void *data)
{
	struct parasite_unmap_args *args = data;

	sys_munmap(args->parasite_start, args->parasite_len);
	/*
	 * This call to sys_munmap must never return. Instead, the controlling
	 * process must trap us on the exit from munmap.
	 */

	BUG();
	return -1;
}

static noinline __used int parasite_init_daemon(void *data)
{
	struct parasite_init_args *args = data;
	int ret;

	args->sigreturn_addr = fini_sigreturn;
	sigframe = args->sigframe;

	ret = tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (tsock < 0) {
		pr_err("Can't create socket: %d\n", tsock);
		goto err;
	}

	ret = sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len);
	if (ret < 0) {
		pr_err("Can't connect the control socket\n");
		goto err;
	}

	futex_set_and_wake(&args->daemon_connected, 1);

	ret = recv_fd(tsock);
	if (ret >= 0) {
		log_set_fd(ret);
		log_set_loglevel(args->log_level);
		ret = 0;
	} else
		goto err;

	parasite_daemon(data);

err:
	futex_set_and_wake(&args->daemon_connected, ret);
	fini();
	BUG();

	return -1;
}

#ifndef __parasite_entry
# define __parasite_entry
#endif

int __used __parasite_entry parasite_service(unsigned int cmd, void *args)
{
	pr_info("Parasite cmd %d/%x process\n", cmd, cmd);

	switch (cmd) {
	case PARASITE_CMD_DUMP_THREAD:
		return dump_thread(args);
	case PARASITE_CMD_INIT_DAEMON:
		return parasite_init_daemon(args);
	case PARASITE_CMD_UNMAP:
		return unmap_itself(args);
	}

	pr_err("Unknown command to parasite: %d\n", cmd);
	return -EINVAL;
}
