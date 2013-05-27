#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "protobuf.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/itimer.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/pagemap.pb-c.h"

#include "syscall.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "kerndat.h"
#include "pstree.h"
#include "net.h"
#include "mem.h"
#include "vdso.h"
#include "restorer.h"

#include <string.h>
#include <stdlib.h>

#include "asm/parasite-syscall.h"
#include "asm/dump.h"
#include "asm/restorer.h"

#define parasite_size		(round_up(sizeof(parasite_blob), PAGE_SIZE))

static int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end)
{
	return ip >= start && ip < (end - code_syscall_size);
}

static int syscall_fits_vma_area(struct vma_area *vma_area)
{
	return can_run_syscall((unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.end);
}

static struct vma_area *get_vma_by_ip(struct list_head *vma_area_list, unsigned long ip)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (vma_area->vma.start >= TASK_SIZE)
			continue;
		if (!(vma_area->vma.prot & PROT_EXEC))
			continue;
		if (syscall_fits_vma_area(vma_area))
			return vma_area;
	}

	return NULL;
}

/* we run at @regs->ip */
int __parasite_execute_trap(struct parasite_ctl *ctl, pid_t pid,
				user_regs_struct_t *regs,
				user_regs_struct_t *regs_orig,
				bool signals_blocked)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

again:
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
		pr_perror("Can't set registers (pid: %d)", pid);
		goto err;
	}

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_perror("Can't continue (pid: %d)", pid);
		goto err;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_perror("Can't get siginfo (pid: %d)", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != ARCH_SI_TRAP) {
retry_signal:
		pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		if (signals_blocked) {
			pr_err("Unexpected %d task interruption, aborting\n", pid);
			goto err;
		}

		/* FIXME: jerr(siginfo.si_code > 0, err_restore); */

		/*
		 * This requires some explanation. If a signal from original
		 * program delivered while we're trying to execute our
		 * injected blob -- we need to setup original registers back
		 * so the kernel would make sigframe for us and update the
		 * former registers.
		 *
		 * Then we should swap registers back to our modified copy
		 * and retry.
		 */

		if (ptrace(PTRACE_SETREGS, pid, NULL, regs_orig)) {
			pr_perror("Can't set registers (pid: %d)", pid);
			goto err;
		}

		if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
			pr_perror("Can't interrupt (pid: %d)", pid);
			goto err;
		}

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)siginfo.si_signo)) {
			pr_perror("Can't continue (pid: %d)", pid);
			goto err;
		}

		if (wait4(pid, &status, __WALL, NULL) != pid) {
			pr_perror("Waited pid mismatch (pid: %d)", pid);
			goto err;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("Task is still running (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
			pr_perror("Can't get siginfo (pid: %d)", pid);
			goto err;
		}

		if (SI_EVENT(siginfo.si_code) != PTRACE_EVENT_STOP)
			goto retry_signal;

		/*
		 * Signal is delivered, so we should update
		 * original registers.
		 */
		{
			user_regs_struct_t r;
			if (ptrace(PTRACE_GETREGS, pid, NULL, &r)) {
				pr_perror("Can't obtain registers (pid: %d)", pid);
				goto err;
			}
			*regs_orig = r;
		}

		goto again;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	return ret;
}

void *parasite_args_s(struct parasite_ctl *ctl, int args_size)
{
	BUG_ON(args_size > ctl->args_size);
	return ctl->addr_args;
}

#define parasite_args(ctl, type) ({				\
		BUILD_BUG_ON(sizeof(type) > PARASITE_ARG_SIZE_MIN);\
		ctl->addr_args;					\
	})

static int parasite_execute_trap_by_id(unsigned int cmd, struct parasite_ctl *ctl, int id)
{
	struct parasite_thread_ctl *thread = &ctl->threads[id];
	user_regs_struct_t regs = thread->regs_orig;
	pid_t pid = thread->tid;
	int ret;

	*ctl->addr_cmd = cmd;

	parasite_setup_regs(ctl->parasite_ip, thread->rstack, &regs);

	ret = __parasite_execute_trap(ctl, pid, &regs, &thread->regs_orig,
					thread->use_sig_blocked);
	if (ret == 0)
		ret = (int)REG_RES(regs);

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	if (ctl->pid.real != pid)
		if (ptrace(PTRACE_SETREGS, pid, NULL, &thread->regs_orig)) {
			pr_perror("Can't restore registers (pid: %d)", pid);
			return -1;
		}

	return ret;
}

static int parasite_execute_trap(unsigned int cmd, struct parasite_ctl *ctl)
{
	return parasite_execute_trap_by_id(cmd, ctl, 0);
}

static int __parasite_send_cmd(int sockfd, struct ctl_msg *m)
{
	int ret;

	ret = send(sockfd, m, sizeof(*m), 0);
	if (ret == -1) {
		pr_perror("Failed to send command %d to daemon %d\n", m->cmd, m->id);
		return -1;
	} else if (ret != sizeof(*m)) {
		pr_err("Message to daemon is trimmed (%d/%d)\n",
		       (int)sizeof(*m), ret);
		return -1;
	}

	pr_debug("Sent msg to daemon %d %d %d %d\n", m->id, m->cmd, m->ack, m->err);
	return 0;
}

static int parasite_wait_ack(int sockfd, int id, unsigned int cmd, struct ctl_msg *m)
{
	int ret;

	pr_debug("Wait for ack %d-%d on daemon socket\n", id, cmd);

	while (1) {
		memzero(m, sizeof(*m));

		ret = recv(sockfd, m, sizeof(*m), MSG_WAITALL);
		if (ret == -1) {
			pr_perror("Failed to read ack from %d", id);
			return -1;
		} else if (ret != sizeof(*m)) {
			pr_err("Message reply from daemon is trimmed (%d/%d)\n",
			       (int)sizeof(*m), ret);
			return -1;
		}
		pr_debug("Fetched ack: %d %d %d %d\n",
			 m->id, m->cmd, m->ack, m->err);

		if (m->id != id || m->cmd != cmd || m->ack != cmd) {
			pr_err("Communication error, this is not "
			       "the ack we expected\n");
			return -1;
		}
		return 0;
	}

	return -1;
}

int __parasite_execute_daemon_wait_ack(unsigned int cmd,
					struct parasite_ctl *ctl, int id)
{
	struct ctl_msg m;

	if (parasite_wait_ack(ctl->tsock, id, cmd, &m))
		return -1;

	if (m.err != 0) {
		pr_err("Command %d for daemon %d failed with %d\n",
		       cmd, id, m.err);
		return -1;
	}

	return 0;
}

int __parasite_execute_daemon_by_id(unsigned int cmd,
				struct parasite_ctl *ctl, int id, bool wait_ack)
{
	struct ctl_msg m;

	m = ctl_msg_cmd(id, cmd);
	if (__parasite_send_cmd(ctl->tsock, &m))
		return -1;

	if (wait_ack)
		return __parasite_execute_daemon_wait_ack(cmd, ctl, id);

	return 0;
}

static int parasite_execute_daemon_by_id(unsigned int cmd,
					struct parasite_ctl *ctl, int id)
{
	return __parasite_execute_daemon_by_id(cmd, ctl, id, true);
}

int parasite_execute_daemon(unsigned int cmd, struct parasite_ctl *ctl)
{
	return parasite_execute_daemon_by_id(cmd, ctl, 0);
}

static int munmap_seized(struct parasite_ctl *ctl, void *addr, size_t length)
{
	unsigned long x;

	return syscall_seized(ctl, __NR_munmap, &x,
			(unsigned long)addr, length, 0, 0, 0, 0);
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX,
			"X/crtools-pr-%d", key);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

int parasite_send_fd(struct parasite_ctl *ctl, int fd)
{
	if (send_fd(ctl->tsock, NULL, 0, fd) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
	}
	return 0;
}

static int parasite_set_logfd(struct parasite_ctl *ctl, pid_t pid)
{
	int ret;
	struct parasite_log_args *a;

	ret = parasite_send_fd(ctl, log_get_fd());
	if (ret)
		return ret;

	a = parasite_args(ctl, struct parasite_log_args);
	a->log_level = log_get_loglevel();

	ret = parasite_execute_trap(PARASITE_CMD_CFG_LOG, ctl);
	if (ret < 0)
		return ret;

	return 0;
}

static int parasite_init(struct parasite_ctl *ctl, pid_t pid, int nr_threads)
{
	struct parasite_init_args *args;
	static int sock = -1;

	args = parasite_args(ctl, struct parasite_init_args);

	pr_info("Putting tsock into pid %d\n", pid);
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, getpid());
	args->p_addr_len = gen_parasite_saddr(&args->p_addr, pid);
	args->nr_threads = nr_threads;
	args->sigframe = ctl->threads[0].rsigframe;
	args->id = 0;

	if (sock == -1) {
		int rst = -1;

		if (current_ns_mask & CLONE_NEWNET) {
			pr_info("Switching to %d's net for tsock creation\n", pid);

			if (switch_ns(pid, &net_ns_desc, &rst))
				return -1;
		}

		sock = socket(PF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0)
			pr_perror("Can't create socket");

		if (rst > 0 && restore_ns(rst, &net_ns_desc) < 0)
			return -1;
		if (sock < 0)
			return -1;

		if (bind(sock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

	} else {
		struct sockaddr addr = { .sa_family = AF_UNSPEC, };

		/*
		 * When the peer of a dgram socket dies the original socket
		 * remains in connected state, thus denying any connections
		 * from "other" sources. Unconnect the socket by hands thus
		 * allowing for parasite to connect back.
		 */

		if (connect(sock, &addr, sizeof(addr)) < 0) {
			pr_perror("Can't unconnect");
			goto err;
		}
	}

	if (parasite_execute_trap(PARASITE_CMD_INIT, ctl) < 0) {
		pr_err("Can't init parasite\n");
		goto err;
	}

	ctl->threads[0].sig_blocked = args->sig_blocked;
	ctl->threads[0].use_sig_blocked = true;

	if (connect(sock, (struct sockaddr *)&args->p_addr, args->p_addr_len) < 0) {
		pr_perror("Can't connect a transport socket");
		goto err;
	}

	ctl->tsock = sock;
	return 0;
err:
	close_safe(&sock);
	return -1;
}

static int parasite_daemonize(struct parasite_ctl *ctl, int id)
{
	struct parasite_thread_ctl *thread = &ctl->threads[id];
	pid_t pid = thread->tid;
	user_regs_struct_t regs;
	struct ctl_msg m = { };
	struct parasite_init_args *args;

	*ctl->addr_cmd = PARASITE_CMD_DAEMONIZE;

	args = parasite_args(ctl, struct parasite_init_args);
	args->id = id;

	regs = thread->regs_orig;
	parasite_setup_regs(ctl->parasite_ip, thread->rstack, &regs);

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs)) {
		pr_perror("Can't set registers (pid: %d)", pid);
		goto err;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_perror("Can't continue (pid: %d)\n", pid);
		ptrace(PTRACE_SETREGS, pid, NULL, thread->regs_orig);
		goto err;
	}

	pr_info("Wait for parasite being daemonized...\n");

	if (parasite_wait_ack(ctl->tsock, id, PARASITE_CMD_DAEMONIZE, &m)) {
		pr_err("Can't switch parasite %d to daemon mode %d\n",
		       pid, m.err);
		goto err;
	}

	thread->daemonized = true;
	pr_info("Parasite %d has been switched to daemon mode\n", pid);
	return 0;

err:
	return -1;
}

int parasite_dump_thread_seized(struct parasite_ctl *ctl, int id,
				struct pid *tid, CoreEntry *core)
{
	struct parasite_dump_thread *args;
	int ret;

	args = parasite_args(ctl, struct parasite_dump_thread);
	args->id = id;

	ret = parasite_execute_daemon_by_id(PARASITE_CMD_DUMP_THREAD, ctl, id);

	CORE_THREAD_ARCH_INFO(core)->clear_tid_addr = encode_pointer(args->tid_addr);
	tid->virt = args->tid;
	core_put_tls(core, args->tls);

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_sa_args *args;
	int ret, sig, fd;
	SaEntry se = SA_ENTRY__INIT;

	args = parasite_args(ctl, struct parasite_dump_sa_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	fd = fdset_fd(cr_fdset, CR_FD_SIGACT);

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		ASSIGN_TYPED(se.sigaction, encode_pointer(args->sas[i].rt_sa_handler));
		ASSIGN_TYPED(se.flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(se.restorer, encode_pointer(args->sas[i].rt_sa_restorer));
		ASSIGN_TYPED(se.mask, args->sas[i].rt_sa_mask.sig[0]);

		if (pb_write_one(fd, &se, PB_SIGACT) < 0)
			return -1;
	}

	return 0;
}

static int dump_one_timer(struct itimerval *v, int fd)
{
	ItimerEntry ie = ITIMER_ENTRY__INIT;

	ie.isec = v->it_interval.tv_sec;
	ie.iusec = v->it_interval.tv_usec;
	ie.vsec = v->it_value.tv_sec;
	ie.vusec = v->it_value.tv_usec;

	return pb_write_one(fd, &ie, PB_ITIMERS);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_itimers_args *args;
	int ret, fd;

	args = parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = parasite_execute_daemon(PARASITE_CMD_DUMP_ITIMERS, ctl);
	if (ret < 0)
		return ret;

	fd = fdset_fd(cr_fdset, CR_FD_ITIMERS);

	ret = dump_one_timer(&args->real, fd);
	if (!ret)
		ret = dump_one_timer(&args->virt, fd);
	if (!ret)
		ret = dump_one_timer(&args->prof, fd);

	return ret;
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	struct parasite_dump_misc *ma;

	ma = parasite_args(ctl, struct parasite_dump_misc);
	if (parasite_execute_daemon(PARASITE_CMD_DUMP_MISC, ctl) < 0)
		return -1;

	*misc = *ma;
	return 0;
}

struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd)
{
	struct parasite_tty_args *p;

	p = parasite_args(ctl, struct parasite_tty_args);
	p->fd = fd;

	if (parasite_execute_daemon(PARASITE_CMD_DUMP_TTY, ctl) < 0)
		return NULL;

	return p;
}

int parasite_dump_creds(struct parasite_ctl *ctl, CredsEntry *ce)
{
	struct parasite_dump_creds *pc;

	pc = parasite_args(ctl, struct parasite_dump_creds);
	if (parasite_execute_daemon(PARASITE_CMD_DUMP_CREDS, ctl) < 0)
		return -1;

	ce->secbits = pc->secbits;
	ce->n_groups = pc->ngroups;

	/*
	 * Achtung! We leak the parasite args pointer to the caller.
	 * It's not safe in general, but in our case is OK, since the
	 * latter doesn't go to parasite before using the data in it.
	 */

	BUILD_BUG_ON(sizeof(ce->groups[0]) != sizeof(pc->groups[0]));
	ce->groups = pc->groups;
	return 0;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl,
		struct parasite_drain_fd *dfds, int *lfds, struct fd_opts *opts)
{
	int ret = -1, size;
	struct parasite_drain_fd *args;

	size = drain_fds_size(dfds);
	args = parasite_args_s(ctl, size);
	memcpy(args, dfds, size);

	ret = __parasite_execute_daemon_by_id(PARASITE_CMD_DRAIN_FDS, ctl,
					       0, false);
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	ret = recv_fds(ctl->tsock, lfds, dfds->nr_fds, opts);
	if (ret)
		pr_err("Can't retrieve FDs from socket\n");

	ret |= __parasite_execute_daemon_wait_ack(PARASITE_CMD_DRAIN_FDS, ctl, 0);
err:
	return ret;
}

/*
 * Find out proxy vdso vma and drop it from the list. Also
 * fix vdso status on vmas if wrong status found.
 */
int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			struct vm_area_list *vma_area_list)
{
	unsigned long proxy_addr = VDSO_BAD_ADDR;
	struct parasite_vdso_vma_entry *args;
	struct vma_area *marked = NULL;
	struct vma_area *vma;
	int fd, ret = -1;
	off_t off;
	u64 pfn;

	args = parasite_args(ctl, struct parasite_vdso_vma_entry);
	fd = open_proc(pid, "pagemap");
	if (fd < 0)
		return -1;

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_area_is(vma, VMA_AREA_REGULAR))
			continue;

		if ((vma->vma.prot & VDSO_PROT) != VDSO_PROT)
			continue;

		/*
		 * I need to poke every potentially marked vma,
		 * otherwise if task never called for vdso functions
		 * page frame number won't be reported.
		 */
		args->start = vma->vma.start;
		args->len = vma_area_len(vma);

		if (parasite_execute_daemon(PARASITE_CMD_CHECK_VDSO_MARK, ctl)) {
			pr_err("vdso: Parasite failed to poke for mark\n");
			ret = -1;
			goto err;
		}

		/*
		 * Defer handling marked vdso.
		 */
		if (unlikely(args->is_marked)) {
			BUG_ON(args->proxy_addr == VDSO_BAD_ADDR);
			BUG_ON(marked);
			marked = vma;
			proxy_addr = args->proxy_addr;
			continue;
		}

		off = (vma->vma.start / PAGE_SIZE) * sizeof(u64);
		if (lseek(fd, off, SEEK_SET) != off) {
			pr_perror("Failed to seek address %lx\n", vma->vma.start);
			ret = -1;
			goto err;
		}

		ret = read(fd, &pfn, sizeof(pfn));
		if (ret < 0 || ret != sizeof(pfn)) {
			pr_perror("Can't read pme for pid %d", pid);
			ret = -1;
			goto err;
		}

		pfn = PME_PFRAME(pfn);
		BUG_ON(!pfn);

		/*
		 * Set proper VMA statuses.
		 */
		if (pfn == vdso_pfn) {
			if (!vma_area_is(vma, VMA_AREA_VDSO)) {
				pr_debug("vdso: Restore status by pfn at %lx\n",
					 (long)vma->vma.start);
				vma->vma.status |= VMA_AREA_VDSO;
			}
		} else {
			if (vma_area_is(vma, VMA_AREA_VDSO)) {
				pr_debug("vdso: Drop mishinted status at %lx\n",
					 (long)vma->vma.start);
				vma->vma.status &= ~VMA_AREA_VDSO;
			}
		}
	}

	/*
	 * There is marked vdso, it means such vdso is autogenerated
	 * and must be dropped from vma list.
	 */
	if (marked) {
		pr_debug("vdso: Found marked at %lx (proxy at %lx)\n",
			 (long)marked->vma.start, (long)proxy_addr);

		/*
		 * Don't forget to restore the proxy vdso status, since
		 * it's being not recognized by the kernel as vdso.
		 */
		list_for_each_entry(vma, &vma_area_list->h, list) {
			if (vma->vma.start == proxy_addr) {
				vma->vma.status |= VMA_AREA_REGULAR | VMA_AREA_VDSO;
				pr_debug("vdso: Restore proxy status at %lx\n",
					 (long)vma->vma.start);
				break;
			}
		}

		pr_debug("vdso: Droppping marked vdso at %lx\n",
			 (long)vma->vma.start);
		list_del(&marked->list);
		xfree(marked);
	}
	ret = 0;
err:
	close(fd);
	return ret;
}

int parasite_get_proc_fd_seized(struct parasite_ctl *ctl)
{
	int ret = -1, fd;

	ret = __parasite_execute_daemon_by_id(PARASITE_CMD_GET_PROC_FD, ctl,
					       0, false);
	if (ret) {
		pr_err("Parasite failed to get proc fd\n");
		return ret;
	}

	fd = recv_fd(ctl->tsock);
	if (fd < 0)
		pr_err("Can't retrieve FD from socket\n");
	if (__parasite_execute_daemon_wait_ack(PARASITE_CMD_GET_PROC_FD, ctl, 0)) {
		close(fd);
		return -1;
	}

	return fd;
}

int parasite_init_threads_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	struct parasite_init_args *args;
	int ret = 0, i;

	args = parasite_args(ctl, struct parasite_init_args);

	for (i = 1; i < item->nr_threads; i++) {
		pid_t tid = item->threads[i].real;
		user_regs_struct_t *regs_orig = &ctl->threads[i].regs_orig;

		ctl->threads[i].tid = tid;
		ctl->nr_threads++;

		args->id = i;
		args->sigframe = ctl->threads[i].rsigframe;

		ret = ptrace(PTRACE_GETREGS, tid, NULL, regs_orig);
		if (ret) {
			pr_perror("Can't obtain registers (pid: %d)", tid);
			goto err;
		}

		ret = parasite_execute_trap_by_id(PARASITE_CMD_INIT_THREAD, ctl, i);
		if (ret) {
			pr_err("Can't init thread in parasite %d\n", tid);
			goto err;
		}

		ret = get_task_regs(tid, *regs_orig, item->core[i]);
		if (ret) {
			pr_err("Can't obtain regs for thread %d\n", tid);
			goto err;
		}

		ctl->threads[i].sig_blocked = args->sig_blocked;
		ctl->threads[i].use_sig_blocked = true;

		if (parasite_daemonize(ctl, i))
			goto err;
	}

	return 0;
err:
	return -1 ;
}

static int parasite_fini_seized(struct parasite_ctl *ctl)
{
	int status, ret = 0, i, nr = 0, nr_dmnz = 0;

	/* Start to trace syscalls for each thread */
	for (i = 0; i < ctl->nr_threads; i++) {
		pid_t pid = ctl->threads[i].tid;

		if (!ctl->threads[i].daemonized)
			break;

		ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);

		pr_debug("Waiting for %d to trap\n", pid);
		if (wait4(pid, &status, __WALL, NULL) != pid) {
			pr_perror("Waited pid mismatch (pid: %d)", pid);
			return -1;
		}

		pr_debug("Daemon %d exited trapping\n", pid);
		if (!WIFSTOPPED(status)) {
			pr_err("Task is still running (pid: %d)\n", pid);
			return -1;
		}

		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		nr_dmnz++;
	}

	ret = __parasite_execute_daemon_by_id(PARASITE_CMD_FINI, ctl, 0, false);
	if (ret)
		return -1;

	/* Stop all threads on the enter point in sys_rt_sigreturn */
	while (1) {
		user_regs_struct_t regs;
		pid_t pid;

		pid = wait4(-1, &status, __WALL, NULL);
		if (pid < 0) {
			pr_perror("wait4 failed");
			return -1;
		}

		pr_debug("%d was trapped\n", pid);
		if (!WIFSTOPPED(status)) {
			pr_err("%d\n", status);
			return -1;
		}
		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		pr_debug("%d is going to execute the syscall %lx\n", pid, regs.orig_ax);
		if (regs.orig_ax == __NR_rt_sigreturn) {
			nr++;
			pr_debug("%d was stopped\n", pid);
			if (nr == nr_dmnz)
				break;
			continue;
		}

		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}
	}

	/* Stop all threads on the exit point from sys_rt_sigreturn */
	for (i = 0; i < ctl->nr_threads; i++) {
		pid_t pid = ctl->threads[i].tid;

		if (!ctl->threads[i].daemonized)
			break;

		ctl->threads[i].use_sig_blocked = false;

		ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret) {
			pr_perror("ptrace");
			return -1;
		}

		if (wait4(pid, &status, __WALL, NULL) != pid) {
			pr_perror("wait4 failed");
			return -1;
		}

		pr_debug("Trap %d\n", pid);
		if (!WIFSTOPPED(status)) {
			pr_err("%d\n", status);
			return -1;
		}
	}

	return ret;
}

int parasite_cure_remote(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->parasite_ip)
		if (parasite_fini_seized(ctl))
			return -1;

	ctl->tsock = -1;

	if (ctl->remote_map) {
		if (munmap_seized(ctl, (void *)ctl->remote_map, ctl->map_length)) {
			pr_err("munmap_seized failed (pid: %d)\n", ctl->pid.real);
			ret = -1;
		}
	}

	if (ptrace_poke_area(ctl->pid.real, (void *)ctl->code_orig,
			     (void *)ctl->syscall_ip, sizeof(ctl->code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid.real);
		ret = -1;
	}

	if (ptrace(PTRACE_SETREGS, ctl->pid.real, NULL, &ctl->threads[0].regs_orig)) {
		pr_err("Can't restore registers (pid: %d)\n", ctl->pid.real);
		ret = -1;
	}

	return ret;
}

int parasite_cure_local(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->local_map) {
		if (munmap(ctl->local_map, ctl->map_length)) {
			pr_err("munmap failed (pid: %d)\n", ctl->pid.real);
			ret = -1;
		}
	}

	free(ctl);
	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl)
{
	int ret;

	ret = parasite_cure_remote(ctl);
	if (!ret)
		ret = parasite_cure_local(ctl);

	return ret;
}

struct parasite_ctl *parasite_prep_ctl(pid_t pid, struct vm_area_list *vma_area_list, unsigned int nr_threads)
{
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;

	BUG_ON(nr_threads == 0);

	if (!arch_can_dump_task(pid))
		goto err;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl) + nr_threads * sizeof(ctl->threads[0]));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	ctl->tsock = -1;
	ctl->nr_threads = 1;
	ctl->threads[0].tid = pid;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &ctl->threads[0].regs_orig)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
		goto err;
	}

	vma_area = get_vma_by_ip(&vma_area_list->h, REG_IP(ctl->threads[0].regs_orig));
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
		       "bootstrap code (pid: %d)\n", pid);
		goto err;
	}

	ctl->pid.real	= pid;
	ctl->pid.virt	= 0;
	ctl->syscall_ip	= vma_area->vma.start;

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(ctl->code_orig, code_syscall, sizeof(ctl->code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->syscall_ip,
			     (void *)ctl->code_orig, sizeof(ctl->code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		goto err;
	}

	return ctl;

err:
	xfree(ctl);
	return NULL;
}

int parasite_map_exchange(struct parasite_ctl *ctl, unsigned long size)
{
	int fd;

	ctl->remote_map = mmap_seized(ctl, NULL, size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", ctl->pid.real);
		return -1;
	}

	ctl->map_length = round_up(size, PAGE_SIZE);

	fd = open_proc_rw(ctl->pid.real, "map_files/%p-%p",
		 ctl->remote_map, ctl->remote_map + ctl->map_length);
	if (fd < 0)
		return -1;

	ctl->local_map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		return -1;
	}

	return 0;
}

static unsigned long parasite_args_size(struct vm_area_list *vmas, struct parasite_drain_fd *dfds)
{
	unsigned long size = PARASITE_ARG_SIZE_MIN;

	if (dfds)
		size = max(size, (unsigned long)drain_fds_size(dfds));
	size = max(size, (unsigned long)dump_pages_args_size(vmas));

	return round_up(size, PAGE_SIZE);
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item,
		struct vm_area_list *vma_area_list, struct parasite_drain_fd *dfds)
{
	int ret, i;
	struct parasite_ctl *ctl;
	unsigned long p;

	BUG_ON(item->threads[0].real != pid);

	if (pstree_alloc_cores(item))
		return NULL;

	ctl = parasite_prep_ctl(pid, vma_area_list, item->nr_threads);
	if (!ctl)
		return NULL;

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */

	ctl->args_size = parasite_args_size(vma_area_list, dfds);
	ret = parasite_map_exchange(ctl, parasite_size + ctl->args_size +
					 item->nr_threads * RESTORE_STACK_SIGFRAME +
					 item->nr_threads * PARASITE_STACK_SIZE);
	if (ret)
		goto err_restore;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	/* Setup the rest of a control block */
	ctl->parasite_ip	= (unsigned long)parasite_sym(ctl->remote_map, __export_parasite_head_start);
	ctl->addr_cmd		= parasite_sym(ctl->local_map, __export_parasite_cmd);
	ctl->addr_args		= parasite_sym(ctl->local_map, __export_parasite_args);

	p = parasite_size + ctl->args_size;
	for (i = 0; i < item->nr_threads; i++) {
		struct parasite_thread_ctl *thread = &ctl->threads[i];

		thread->rstack		= ctl->remote_map + p;
		thread->rsigframe	= ctl->remote_map + p + PARASITE_STACK_SIZE;
		thread->sigframe	= ctl->local_map  + p + PARASITE_STACK_SIZE;

		p += PARASITE_STACK_SIZE + RESTORE_STACK_SIGFRAME;
	}

	ret = parasite_init(ctl, pid, item->nr_threads);
	if (ret) {
		pr_err("%d: Can't create a transport socket\n", pid);
		goto err_restore;
	}

	ret = get_task_regs(pid, ctl->threads[0].regs_orig, item->core[0]);
	if (ret) {
		pr_err("Can't obtain regs for thread %d\n", pid);
		goto err_restore;
	}

	ret = parasite_set_logfd(ctl, pid);
	if (ret) {
		pr_err("%d: Can't set a logging descriptor\n", pid);
		goto err_restore;
	}

	if (parasite_daemonize(ctl, 0))
		goto err_restore;

	ret = parasite_init_threads_seized(ctl, item);
	if (ret)
		goto err_restore;

	for (i = 0; i < item->nr_threads; i++) {
		struct parasite_thread_ctl *thread = &ctl->threads[i];

		if (i == 0)
			memcpy(&item->core[i]->tc->blk_sigset,
				&thread->sig_blocked, sizeof(k_rtsigset_t));
		else {
			memcpy(&item->core[i]->thread_core->blk_sigset,
				&thread->sig_blocked, sizeof(k_rtsigset_t));
			item->core[i]->thread_core->has_blk_sigset = true;
		}

		if (construct_sigframe(thread->sigframe, thread->rsigframe, item->core[i]))
			goto err_restore;
	}

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;
}

