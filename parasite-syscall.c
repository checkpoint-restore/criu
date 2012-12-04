#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "protobuf.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/itimer.pb-c.h"
#include "protobuf/creds.pb-c.h"

#include "syscall.h"
#include "ptrace.h"
#include "processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"
#include "crtools.h"
#include "namespaces.h"
#include "pstree.h"

#include <string.h>
#include <stdlib.h>

#ifdef CONFIG_X86_64
static const char code_syscall[] = {0x0f, 0x05, 0xcc, 0xcc,
				    0xcc, 0xcc, 0xcc, 0xcc};

#define code_syscall_size	(round_up(sizeof(code_syscall), sizeof(long)))
#define parasite_size		(round_up(sizeof(parasite_blob), sizeof(long)))

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
		if (!in_vma_area(vma_area, ip))
			continue;
		if (!(vma_area->vma.prot & PROT_EXEC))
			continue;
		if (syscall_fits_vma_area(vma_area))
			return vma_area;
	}

	return NULL;
}

/* Note it's destructive on @regs */
static void parasite_setup_regs(unsigned long new_ip, user_regs_struct_t *regs)
{
	regs->ip = new_ip;

	/* Avoid end of syscall processing */
	regs->orig_ax = -1;

	/* Make sure flags are in known state */
	regs->flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF);
}

/* we run at @regs->ip */
static int __parasite_execute(struct parasite_ctl *ctl, pid_t pid, user_regs_struct_t *regs)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

again:
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
		pr_err("Can't set registers (pid: %d)\n", pid);
		goto err;
	}

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_err("Can't continue (pid: %d)\n", pid);
		goto err;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_err("Waited pid mismatch (pid: %d)\n", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_err("Can't get siginfo (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != SI_KERNEL) {
retry_signal:
		pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		if (ctl->signals_blocked) {
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

		if (ptrace(PTRACE_SETREGS, pid, NULL, &ctl->regs_orig)) {
			pr_err("Can't set registers (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
			pr_err("Can't interrupt (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)siginfo.si_signo)) {
			pr_err("Can't continue (pid: %d)\n", pid);
			goto err;
		}

		if (wait4(pid, &status, __WALL, NULL) != pid) {
			pr_err("Waited pid mismatch (pid: %d)\n", pid);
			goto err;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("Task is still running (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
			pr_err("Can't get siginfo (pid: %d)\n", pid);
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
				pr_err("Can't obtain registers (pid: %d)\n", pid);
				goto err;
			}
			ctl->regs_orig = r;
		}

		goto again;
	}

	/*
	 * We've reached this point iif int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	return ret;
}

static void *parasite_args_s(struct parasite_ctl *ctl, int args_size)
{
	BUG_ON(args_size > PARASITE_ARG_SIZE);
	return ctl->addr_args;
}

#define parasite_args(ctl, type) ({				\
		BUILD_BUG_ON(sizeof(type) > PARASITE_ARG_SIZE);	\
		ctl->addr_args;					\
	})

static int parasite_execute_by_pid(unsigned int cmd, struct parasite_ctl *ctl, pid_t pid)
{
	int ret;
	user_regs_struct_t regs_orig, regs;

	if (ctl->pid == pid)
		regs = ctl->regs_orig;
	else {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs_orig)) {
			pr_err("Can't obtain registers (pid: %d)\n", pid);
			return -1;
		}
		regs = regs_orig;
	}

	*ctl->addr_cmd = cmd;

	parasite_setup_regs(ctl->parasite_ip, &regs);

	ret = __parasite_execute(ctl, pid, &regs);
	if (ret == 0)
		ret = (int)regs.ax;

	if (ret)
		pr_err("Parasite exited with %d\n", ret);

	if (ctl->pid != pid)
		if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig)) {
			pr_err("Can't restore registers (pid: %d)\n", ctl->pid);
			return -1;
		}

	return ret;
}

static int parasite_execute(unsigned int cmd, struct parasite_ctl *ctl)
{
	return parasite_execute_by_pid(cmd, ctl, ctl->pid);
}

static void *mmap_seized(struct parasite_ctl *ctl,
			 void *addr, size_t length, int prot,
			 int flags, int fd, off_t offset)
{
	user_regs_struct_t regs = ctl->regs_orig;
	void *map = NULL;
	int ret;

	regs.ax  = (unsigned long)__NR_mmap;	/* mmap		*/
	regs.di  = (unsigned long)addr;		/* @addr	*/
	regs.si  = (unsigned long)length;	/* @length	*/
	regs.dx  = (unsigned long)prot;		/* @prot	*/
	regs.r10 = (unsigned long)flags;	/* @flags	*/
	regs.r8  = (unsigned long)fd;		/* @fd		*/
	regs.r9  = (unsigned long)offset;	/* @offset	*/

	parasite_setup_regs(ctl->syscall_ip, &regs);

	ret = __parasite_execute(ctl, ctl->pid, &regs);
	if (ret)
		goto err;

	if ((long)regs.ax > 0)
		map = (void *)regs.ax;
err:
	return map;
}

static int munmap_seized(struct parasite_ctl *ctl, void *addr, size_t length)
{
	user_regs_struct_t regs = ctl->regs_orig;
	int ret;

	regs.ax = (unsigned long)__NR_munmap;	/* mmap		*/
	regs.di = (unsigned long)addr;		/* @addr	*/
	regs.si = (unsigned long)length;	/* @length	*/

	parasite_setup_regs(ctl->syscall_ip, &regs);

	ret = __parasite_execute(ctl, ctl->pid, &regs);
	if (!ret)
		ret = (int)regs.ax;

	return ret;
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

static int parasite_send_fd(struct parasite_ctl *ctl, int fd)
{
	if (send_fd(ctl->tsock, NULL, 0, fd) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
	}
	return 0;
}

static int parasite_prep_file(int fd, struct parasite_ctl *ctl)
{
	int ret;

	if (fchmod(fd, CR_FD_PERM_DUMP)) {
		pr_perror("Can't change permissions on file");
		return -1;
	}

	ret = parasite_send_fd(ctl, fd);
	if (ret)
		return ret;

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

	ret = parasite_execute(PARASITE_CMD_CFG_LOG, ctl);
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
	args->h_addr_len = gen_parasite_saddr(&args->h_addr, 0);
	args->p_addr_len = gen_parasite_saddr(&args->p_addr, pid);
	args->nr_threads = nr_threads;

	if (sock == -1) {
		int rst = -1;

		if (opts.namespaces_flags & CLONE_NEWNET) {
			pr_info("Switching to %d's net for tsock creation\n", pid);

			if (switch_ns(pid, CLONE_NEWNET, "net", &rst))
				return -1;
		}

		sock = socket(PF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0) {
			pr_perror("Can't create socket");
			return -1;
		}

		if (bind(sock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0) {
			pr_perror("Can't bind socket");
			goto err;
		}

		if (rst > 0 && restore_ns(rst, CLONE_NEWNET) < 0)
			goto err;
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

	if (parasite_execute(PARASITE_CMD_INIT, ctl) < 0) {
		pr_err("Can't init parasite\n");
		goto err;
	}

	if (connect(sock, (struct sockaddr *)&args->p_addr, args->p_addr_len) < 0) {
		pr_perror("Can't connect a transport socket");
		goto err;
	}

	ctl->tsock = sock;
	return 0;
err:
	close(sock);
	return -1;
}

int parasite_dump_thread_seized(struct parasite_ctl *ctl, pid_t pid,
					unsigned int **tid_addr, pid_t *tid,
					void *blocked)
{
	struct parasite_dump_thread *args;
	int ret;

	args = parasite_args(ctl, struct parasite_dump_thread);

	ret = parasite_execute_by_pid(PARASITE_CMD_DUMP_THREAD, ctl, pid);

	memcpy(blocked, &args->blocked, sizeof(args->blocked));
	*tid_addr = args->tid_addr;
	*tid = args->tid;

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_sa_args *args;
	int ret, sig, fd;
	SaEntry se = SA_ENTRY__INIT;

	args = parasite_args(ctl, struct parasite_dump_sa_args);

	ret = parasite_execute(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	fd = fdset_fd(cr_fdset, CR_FD_SIGACT);

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		ASSIGN_TYPED(se.sigaction, args->sas[i].rt_sa_handler);
		ASSIGN_TYPED(se.flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(se.restorer, args->sas[i].rt_sa_restorer);
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
	ie.vusec = v->it_value.tv_sec;

	return pb_write_one(fd, &ie, PB_ITIMERS);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	struct parasite_dump_itimers_args *args;
	int ret, fd;

	args = parasite_args(ctl, struct parasite_dump_itimers_args);

	ret = parasite_execute(PARASITE_CMD_DUMP_ITIMERS, ctl);
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
	if (parasite_execute(PARASITE_CMD_DUMP_MISC, ctl) < 0)
		return -1;

	*misc = *ma;
	return 0;
}

struct parasite_tty_args *parasite_dump_tty(struct parasite_ctl *ctl, int fd)
{
	struct parasite_tty_args *p;

	p = parasite_args(ctl, struct parasite_tty_args);
	p->fd = fd;

	if (parasite_execute(PARASITE_CMD_DUMP_TTY, ctl) < 0)
		return NULL;

	return p;
}

int parasite_dump_creds(struct parasite_ctl *ctl, CredsEntry *ce)
{
	struct parasite_dump_creds *pc;

	pc = parasite_args(ctl, struct parasite_dump_creds);
	if (parasite_execute(PARASITE_CMD_DUMP_CREDS, ctl) < 0)
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

/*
 * This routine drives parasite code (been previously injected into a victim
 * process) and tells it to dump pages into the file.
 */
int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset)
{
	struct parasite_dump_pages_args *parasite_dumppages;
	unsigned long nrpages_dumped = 0, nrpages_skipped = 0, nrpages_total = 0;
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(fdset_fd(cr_fdset, CR_FD_PAGES), ctl);
	if (ret < 0)
		goto out;

	ret = parasite_execute(PARASITE_CMD_DUMPPAGES_INIT, ctl);
	if (ret < 0) {
		pr_err("Dumping pages failed with %i\n", ret);
		goto out;
	}

	parasite_dumppages = parasite_args(ctl, struct parasite_dump_pages_args);

	list_for_each_entry(vma_area, vma_area_list, list) {

		/*
		 * The special areas are not dumped.
		 */
		if (!(vma_area->vma.status & VMA_AREA_REGULAR))
			continue;

		/* No dumps for file-shared mappings */
		if (vma_area->vma.status & VMA_FILE_SHARED)
			continue;

		/* No dumps for SYSV IPC mappings */
		if (vma_area->vma.status & VMA_AREA_SYSVIPC)
			continue;

		if (vma_area_is(vma_area, VMA_ANON_SHARED))
			continue;

		parasite_dumppages->vma_entry = vma_area->vma;

		if (!vma_area_is(vma_area, VMA_ANON_PRIVATE) &&
		    !vma_area_is(vma_area, VMA_FILE_PRIVATE)) {
			pr_warn("Unexpected VMA area found\n");
			continue;
		}

		ret = parasite_execute(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret) {
			pr_err("Dumping pages failed with %d\n", ret);
			goto out_fini;
		}

		pr_info("vma %lx-%lx  dumped: %lu pages %lu skipped %lu total\n",
				vma_area->vma.start, vma_area->vma.end,
				parasite_dumppages->nrpages_dumped,
				parasite_dumppages->nrpages_skipped,
				parasite_dumppages->nrpages_total);

		nrpages_dumped += parasite_dumppages->nrpages_dumped;
		nrpages_skipped += parasite_dumppages->nrpages_skipped;
		nrpages_total += parasite_dumppages->nrpages_total;
	}

	pr_info("\n");
	pr_info("Summary: %lu dumped %lu skipped %lu total\n",
			nrpages_dumped, nrpages_skipped, nrpages_total);
	ret = 0;

out_fini:
	parasite_execute(PARASITE_CMD_DUMPPAGES_FINI, ctl);
out:
	fchmod(fdset_fd(cr_fdset, CR_FD_PAGES), CR_FD_PERM);
	pr_info("----------------------------------------\n");

	return ret;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl,
		struct parasite_drain_fd *dfds, int *lfds, struct fd_opts *opts)
{
	int ret = -1, size;
	struct parasite_drain_fd *args;

	size = drain_fds_size(dfds);
	args = parasite_args_s(ctl, size);
	memcpy(args, dfds, size);

	ret = parasite_execute(PARASITE_CMD_DRAIN_FDS, ctl);
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	ret = recv_fds(ctl->tsock, lfds, dfds->nr_fds, opts);
	if (ret) {
		pr_err("Can't retrieve FDs from socket\n");
		goto err;
	}

err:
	return ret;
}

int parasite_get_proc_fd_seized(struct parasite_ctl *ctl)
{
	int ret = -1, fd;

	ret = parasite_execute(PARASITE_CMD_GET_PROC_FD, ctl);
	if (ret) {
		pr_err("Parasite failed to get proc fd\n");
		return ret;
	}

	fd = recv_fd(ctl->tsock);
	if (fd < 0) {
		pr_err("Can't retrieve FD from socket\n");
		return fd;
	}

	return fd;
}

int parasite_init_threads_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	int ret = 0, i;

	for (i = 0; i < item->nr_threads; i++) {
		if (item->pid.real == item->threads[i].real)
			continue;

		ret = parasite_execute_by_pid(PARASITE_CMD_INIT_THREAD, ctl,
					      item->threads[i].real);
		if (ret) {
			pr_err("Can't init thread in parasite %d\n",
			       item->threads[i].real);
			break;
		}
	}

	return ret;
}

int parasite_fini_threads_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	int ret = 0, i;

	for (i = 0; i < item->nr_threads; i++) {
		if (item->pid.real == item->threads[i].real)
			continue;

		ret = parasite_execute_by_pid(PARASITE_CMD_FINI_THREAD, ctl,
					      item->threads[i].real);
		/*
		 * Note the thread's fini() can be called even when not
		 * all threads were init()'ed, say we're rolling back from
		 * error happened while we were init()'ing some thread, thus
		 * -ENOENT will be returned but we should continie for the
		 * rest of threads set.
		 *
		 * Strictly speaking we always init() threads in sequence thus
		 * we could simply break the loop once first -ENOENT returned
		 * but I prefer to be on a safe side even if some future changes
		 * would change the code logic.
		 */
		if (ret && ret != -ENOENT) {
			pr_err("Can't fini thread in parasite %d\n",
			       item->threads[i].real);
			break;
		}
	}

	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	int ret = 0;

	ctl->tsock = -1;

	if (ctl->parasite_ip) {
		ctl->signals_blocked = 0;
		parasite_fini_threads_seized(ctl, item);
		parasite_execute(PARASITE_CMD_FINI, ctl);
	}

	if (ctl->remote_map) {
		if (munmap_seized(ctl, (void *)ctl->remote_map, ctl->map_length)) {
			pr_err("munmap_seized failed (pid: %d)\n", ctl->pid);
			ret = -1;
		}
	}

	if (ctl->local_map) {
		if (munmap(ctl->local_map, parasite_size)) {
			pr_err("munmap failed (pid: %d)\n", ctl->pid);
			ret = -1;
		}
	}

	if (ptrace_poke_area(ctl->pid, (void *)ctl->code_orig,
			     (void *)ctl->syscall_ip, sizeof(ctl->code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid);
		ret = -1;
	}

	if (ptrace(PTRACE_SETREGS, ctl->pid, NULL, &ctl->regs_orig)) {
		pr_err("Can't restore registers (pid: %d)\n", ctl->pid);
		ret = -1;
	}

	free(ctl);
	return ret;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item, struct list_head *vma_area_list)
{
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;
	int ret, fd;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	ctl->tsock = -1;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &ctl->regs_orig)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
		goto err;
	}

	vma_area = get_vma_by_ip(vma_area_list, ctl->regs_orig.ip);
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
		       "bootstrap code (pid: %d)\n", pid);
		goto err;
	}

	ctl->pid	= pid;
	ctl->syscall_ip	= vma_area->vma.start;

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	BUILD_BUG_ON(sizeof(code_syscall) != sizeof(ctl->code_orig));
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));

	memcpy(ctl->code_orig, code_syscall, sizeof(ctl->code_orig));
	if (ptrace_swap_area(ctl->pid, (void *)ctl->syscall_ip,
			     (void *)ctl->code_orig, sizeof(ctl->code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		goto err;
	}

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */
	ctl->remote_map = mmap_seized(ctl, NULL, (size_t)parasite_size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", pid);
		goto err_restore;
	}

	ctl->map_length = round_up(parasite_size, PAGE_SIZE);

	fd = open_proc_rw(pid, "map_files/%p-%p",
		 ctl->remote_map, ctl->remote_map + ctl->map_length);
	if (fd < 0)
		goto err_restore;

	ctl->local_map = mmap(NULL, parasite_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		goto err_restore;
	}

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	/* Setup the rest of a control block */
	ctl->parasite_ip	= (unsigned long)parasite_sym(ctl->remote_map, __export_parasite_head_start);
	ctl->addr_cmd		= parasite_sym(ctl->local_map, __export_parasite_cmd);
	ctl->addr_args		= parasite_sym(ctl->local_map, __export_parasite_args);

	ret = parasite_init(ctl, pid, item->nr_threads);
	if (ret) {
		pr_err("%d: Can't create a transport socket\n", pid);
		goto err_restore;
	}

	ctl->signals_blocked = 1;

	ret = parasite_set_logfd(ctl, pid);
	if (ret) {
		pr_err("%d: Can't set a logging descriptor\n", pid);
		goto err_restore;
	}

	ret = parasite_init_threads_seized(ctl, item);
	if (ret)
		goto err_restore;

	return ctl;

err_restore:
	parasite_cure_seized(ctl, item);
	return NULL;

err:
	xfree(ctl);
	return NULL;
}

#else /* CONFIG_X86_64 */
# error x86-32 is not yet implemented
#endif /* CONFIG_X86_64 */
