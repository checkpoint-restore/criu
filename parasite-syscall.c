#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include "crtools.h"
#include "compiler.h"
#include "syscall.h"
#include "types.h"
#include "ptrace.h"
#include "util.h"
#include "util-net.h"
#include "log.h"
#include "sockets.h"
#include "processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"

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

		if (siginfo.si_code >> 8 != PTRACE_EVENT_STOP)
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
	 * Our code is done.
	 */
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
		pr_err("Can't interrupt (pid: %d)\n", pid);
		goto err;
	}

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

	if (siginfo.si_code >> 8 != PTRACE_EVENT_STOP) {
		pr_err("si_code doesn't match (pid: %d si_code: %d)\n",
			pid, siginfo.si_code);
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int parasite_execute_by_pid(unsigned long cmd, struct parasite_ctl *ctl,
			    pid_t pid,
			    parasite_status_t *args, int args_size)
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

	memcpy(ctl->addr_cmd, &cmd, sizeof(cmd));
	if (args)
		memcpy(ctl->addr_args, args, args_size);

	parasite_setup_regs(ctl->parasite_ip, &regs);

	ret = __parasite_execute(ctl, pid, &regs);

	if (args)
		memcpy(args, ctl->addr_args, args_size);

	BUG_ON(ret && !args);

	if (ret)
		pr_err("Parasite exited with %d ret (%li at %li)\n",
		       ret, args->ret, args->line);

	if (ctl->pid != pid)
		if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig)) {
			pr_err("Can't restore registers (pid: %d)\n", ctl->pid);
			return -1;
		}

	return ret;
}

static int parasite_execute(unsigned long cmd, struct parasite_ctl *ctl,
			    parasite_status_t *args, int args_size)
{
	return parasite_execute_by_pid(cmd, ctl, ctl->pid, args, args_size);
}

static void *mmap_seized(struct parasite_ctl *ctl,
			 void *addr, size_t length, int prot,
			 int flags, int fd, off_t offset)
{
	user_regs_struct_t regs = ctl->regs_orig;
	void *map = NULL;
	int ret;

	regs.ax = (unsigned long)__NR_mmap;	/* mmap		*/
	regs.di = (unsigned long)addr;		/* @addr	*/
	regs.si = (unsigned long)length;	/* @length	*/
	regs.dx = (unsigned long)prot;		/* @prot	*/
	regs.r10= (unsigned long)flags;		/* @flags	*/
	regs.r8 = (unsigned long)fd;		/* @fd		*/
	regs.r9 = (unsigned long)offset;	/* @offset	*/

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

static int gen_parasite_saddr(struct sockaddr_un *saddr, pid_t pid)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX,
			"X/crtools-pr-%d", pid);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

static int parasite_send_fd(struct parasite_ctl *ctl, int fd)
{
	struct sockaddr_un saddr;
	int sun_len, ret = -1;
	int sock;

	sun_len = gen_parasite_saddr(&saddr, ctl->pid);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	if (send_fd(sock, &saddr, sun_len, fd) < 0) {
		pr_perror("Can't send file descriptor");
		goto out;
	}
	ret = 0;
out:
	close(sock);
	return ret;
}

static int parasite_prep_file(int type, struct parasite_ctl *ctl,
			      struct cr_fdset *fdset)
{
	int ret;

	if (fchmod(fdset->fds[type], CR_FD_PERM_DUMP)) {
		pr_perror("Can't change permissions on %d file", type);
		return -1;
	}

	ret = parasite_send_fd(ctl, fdset->fds[type]);
	if (ret)
		return ret;

	return 0;
}

static int parasite_file_cmd(char *what, int cmd, int type,
			     struct parasite_ctl *ctl,
			     struct cr_fdset *cr_fdset)
{
	parasite_status_t args = { };
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping %s (pid: %d)\n", what, ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(type, ctl, cr_fdset);
	if (ret < 0)
		goto out;

	ret = parasite_execute(cmd, ctl, (parasite_status_t *)&args, sizeof(args));

	fchmod(cr_fdset->fds[type], CR_FD_PERM);
out:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parasite_init(struct parasite_ctl *ctl, pid_t pid)
{
	struct parasite_init_args args = { };

	args.sun_len = gen_parasite_saddr(&args.saddr, pid);

	return parasite_execute(PARASITE_CMD_INIT, ctl,
				(parasite_status_t *)&args, sizeof(args));
}

static int parasite_set_logfd(struct parasite_ctl *ctl, pid_t pid)
{
	parasite_status_t args = { };
	int ret;

	ret = parasite_send_fd(ctl, log_get_fd());
	if (ret)
		return ret;

	ret = parasite_execute(PARASITE_CMD_SET_LOGFD, ctl, &args, sizeof(args));
	if (ret < 0)
		return ret;

	return 0;
}

int parasite_dump_tid_addr_seized(struct parasite_ctl *ctl, pid_t pid, unsigned int **tid_addr)
{
	struct parasite_dump_tid_addr args = { };
	int ret;

	ret = parasite_execute_by_pid(PARASITE_CMD_DUMP_TID_ADDR, ctl, pid,
			(parasite_status_t *)&args, sizeof(args));

	*tid_addr = args.tid_addr;

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd("sigactions", PARASITE_CMD_DUMP_SIGACTS,
				 CR_FD_SIGACT, ctl, cr_fdset);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd("timers", PARASITE_CMD_DUMP_ITIMERS,
				 CR_FD_ITIMERS, ctl, cr_fdset);
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	return parasite_execute(PARASITE_CMD_DUMP_MISC, ctl,
				(parasite_status_t *)misc,
				sizeof(struct parasite_dump_misc));
}

int parasite_dump_socket_info(struct parasite_ctl *ctl, struct cr_fdset *fdset,
			      struct sk_queue *queue)
{
	int ret, i;
	struct cr_fdset *fds;
	unsigned arg_size;
	struct parasite_dump_sk_queues *arg;
	struct sk_queue_entry *sk_entry;

	if (queue->entries == 0)
		return 0;

	pr_info("Dumping socket queues\n");

	arg_size = sizeof(struct parasite_dump_sk_queues) +
		queue->entries * sizeof(struct sk_queue_item);

	/* FIXME arg size is only enough for ~1k of sockets */
	if (arg_size > PARASITE_ARG_SIZE) {
		pr_err("Too many sockets to drain queue from\n");
		return -1;
	}

	ret = -1;
	arg = xzalloc(arg_size);
	if (arg == NULL)
		goto err_alloc;

	sk_entry = queue->list;
	for (i = 0; i < queue->entries; i++, arg->nr_items++) {
		struct sk_queue_entry *tmp = sk_entry;

		memcpy(&arg->items[i], &sk_entry->item, sizeof(struct sk_queue_item));
		sk_entry = tmp->next;
		xfree(tmp);
	}

	ret = parasite_prep_file(CR_FD_SK_QUEUES, ctl, fdset);
	if (ret < 0)
		goto err_prepf;

	ret = parasite_execute(PARASITE_CMD_DUMP_SK_QUEUES, ctl,
			(parasite_status_t *)arg, arg_size);
	if (ret < 0)
		goto err_exec;

	return 0;

err_exec:
err_prepf:
	xfree(arg);
err_alloc:
	return -1;
}

/*
 * This routine drives parasite code (been previously injected into a victim
 * process) and tells it to dump pages into the file.
 */
int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset)
{
	struct parasite_dump_pages_args parasite_dumppages = { };
	parasite_status_t *st = &parasite_dumppages.status;
	unsigned long nrpages_dumped = 0;
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(CR_FD_PAGES, ctl, cr_fdset);
	if (ret < 0)
		goto out;

	ret = parasite_execute(PARASITE_CMD_DUMPPAGES_INIT, ctl, st, sizeof(*st));
	if (ret < 0) {
		pr_err("Dumping pages failed with %li at %li\n",
				parasite_dumppages.status.ret,
				parasite_dumppages.status.line);
		goto out;
	}

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

		pr_info_vma(vma_area);
		parasite_dumppages.vma_entry = vma_area->vma;

		if (vma_area_is(vma_area, VMA_ANON_PRIVATE) ||
		    vma_area_is(vma_area, VMA_FILE_PRIVATE)) {
			parasite_dumppages.fd_type = PG_PRIV;
		} else {
			pr_warn("Unexpected VMA area found\n");
			continue;
		}

		ret = parasite_execute(PARASITE_CMD_DUMPPAGES, ctl,
				       (parasite_status_t *) &parasite_dumppages,
				       sizeof(parasite_dumppages));
		if (ret) {
			pr_err("Dumping pages failed with %li at %li\n",
				 parasite_dumppages.status.ret,
				 parasite_dumppages.status.line);

			goto out;
		}

		pr_info("  (dumped: %16li pages)\n", parasite_dumppages.nrpages_dumped);
		nrpages_dumped += parasite_dumppages.nrpages_dumped;
	}

	parasite_execute(PARASITE_CMD_DUMPPAGES_FINI, ctl, NULL, 0);

	if (write_img(cr_fdset->fds[CR_FD_PAGES], &zero_page_entry))
		goto out;

	pr_info("\n");
	pr_info("Summary: %16li pages dumped\n", nrpages_dumped);
	ret = 0;

out:
	fchmod(cr_fdset->fds[CR_FD_PAGES], CR_FD_PERM);
	pr_info("----------------------------------------\n");

	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl)
{
	parasite_status_t args = { };
	int ret = 0;

	if (ctl->parasite_ip) {
		ctl->signals_blocked = 0;
		parasite_execute(PARASITE_CMD_FINI, ctl, NULL, 0);
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

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct list_head *vma_area_list)
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
	ctl->parasite_ip	= PARASITE_HEAD_ADDR((unsigned long)ctl->remote_map);
	ctl->addr_cmd		= (void *)PARASITE_CMD_ADDR((unsigned long)ctl->local_map);
	ctl->addr_args		= (void *)PARASITE_ARGS_ADDR((unsigned long)ctl->local_map);

	ret = parasite_init(ctl, pid);
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

	return ctl;

err_restore:
	parasite_cure_seized(ctl);

err:
	xfree(ctl);
	return NULL;
}

#else /* CONFIG_X86_64 */
# error x86-32 is not yet implemented
#endif /* CONFIG_X86_64 */
