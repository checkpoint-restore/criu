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

#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"

#ifdef CONFIG_X86_64
static const char code_syscall[] = {0x0f, 0x05, 0xcc, 0xcc,
				    0xcc, 0xcc, 0xcc, 0xcc};

#define code_syscall_size	(round_up(sizeof(code_syscall), sizeof(long)))
#define parasite_size		(round_up(sizeof(parasite_blob), sizeof(long)))

static int syscall_fits_vma_area(struct vma_area *vma_area)
{
	return can_run_syscall((unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.end);
}

int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end)
{
	return ip >= start && ip < (end - code_syscall_size);
}

static int syscall_seized(pid_t pid, user_regs_struct_t *regs)
{
	unsigned long start_ip;
	char saved[sizeof(code_syscall)];
	siginfo_t siginfo;
	int status;
	int ret = -1;

	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));

	start_ip	= (unsigned long)regs->ip;

	jerr(ptrace_peek_area(pid, (void *)saved, (void *)start_ip, code_syscall_size), err);
	jerr(ptrace_poke_area(pid, (void *)code_syscall, (void *)start_ip, code_syscall_size), err);

	regs->orig_ax	= -1; /* avoid end-of-syscall processing */
again:
	jerr(ptrace(PTRACE_SETREGS, pid, NULL, regs), err_restore);

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	/*
	 * Run the parasite code, at the completion it'll trigger
	 * int3 and inform us that all is done.
	 */

	jerr(ptrace(PTRACE_CONT, pid, NULL, NULL), err_restore_full);
	jerr(wait4(pid, &status, __WALL, NULL) != pid, err_restore_full);
	jerr(!WIFSTOPPED(status), err_restore_full);
	jerr(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo),err_restore_full);

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != SI_KERNEL) {
retry_signal:
		/* pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code); */
		/* FIXME: jerr(siginfo.si_code > 0, err_restore_full); */
		jerr(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL), err_restore_full);
		jerr(ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)siginfo.si_signo), err_restore_full);

		jerr(wait4(pid, &status, __WALL, NULL) != pid, err_restore_full);
		jerr(!WIFSTOPPED(status), err_restore_full);
		jerr(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo), err_restore_full);

		if (siginfo.si_code >> 8 != PTRACE_EVENT_STOP)
			goto retry_signal;

		goto again;
	}

	ret = 0;

	/*
	 * Our code is done.
	 */
	jerr(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL), err_restore_full);
	jerr(ptrace(PTRACE_CONT, pid, NULL, NULL), err_restore_full);

	jerr(wait4(pid, &status, __WALL, NULL) != pid, err_restore_full);
	jerr(!WIFSTOPPED(status), err_restore_full);
	jerr(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo), err_restore_full);

	jerr((siginfo.si_code >> 8 != PTRACE_EVENT_STOP), err_restore_full);

	jerr(ptrace(PTRACE_GETREGS, pid, NULL, regs), err_restore_full);

	ret = 0;

err_restore_full:
err_restore:
	if (ptrace_poke_area(pid, (void *)saved, (void *)start_ip, code_syscall_size)) {
		pr_panic("Crap... Can't restore data (pid: %d)\n", pid);
		ret = -1;
	}
err:
	return ret;
}

static void *mmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	void *mmaped = NULL;
	int ret;

	regs->ax	= (unsigned long)__NR_mmap;	/* mmap		*/
	regs->di	= (unsigned long)addr;		/* @addr	*/
	regs->si	= (unsigned long)length;	/* @length	*/
	regs->dx	= (unsigned long)prot;		/* @prot	*/
	regs->r10	= (unsigned long)flags;		/* @flags	*/
	regs->r8	= (unsigned long)fd;		/* @fd		*/
	regs->r9	= (unsigned long)offset;	/* @offset	*/

	ret = syscall_seized(pid, regs);
	if (ret)
		goto err;
	mmaped = (void *)regs->ax;

	/* error code from the kernel space */
	if ((long)mmaped < 0)
		mmaped = NULL;
err:
	return mmaped;
}

static int munmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length)
{
	int ret;

	regs->ax	= (unsigned long)__NR_munmap;	/* mmap		*/
	regs->di	= (unsigned long)addr;		/* @addr	*/
	regs->si	= (unsigned long)length;	/* @length	*/

	ret = syscall_seized(pid, regs);
	if (!ret)
		ret = (int)regs->ax;

	return ret;
}

static struct vma_area *get_vma_by_ip(struct list_head *vma_area_list, unsigned long ip)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (in_vma_area(vma_area, ip)) {
			if (vma_area->vma.prot & PROT_EXEC) {
				if (syscall_fits_vma_area(vma_area))
					return vma_area;
			}
		}
	}

	return NULL;
}

int parasite_execute(unsigned long cmd, struct parasite_ctl *ctl,
			parasite_status_t *args, int args_size)
{
	parasite_args_t parasite_arg				= { };
	user_regs_struct_t regs, regs_orig;
	int status, ret = -1;
	siginfo_t siginfo;

	jerr(ptrace(PTRACE_GETREGS, ctl->pid, NULL, &regs_orig), err);

	parasite_arg.command		= cmd;
	parasite_arg.args_size		= args_size;
	parasite_arg.args		= args;

	/*
	 * Pass the command first, it's immutable.
	 */
	jerr(ptrace_poke_area((long)ctl->pid, (void *)&parasite_arg.command,
			     (void *)ctl->addr_cmd, sizeof(parasite_arg.command)),
			     err_restore);

again:
		regs = regs_orig;
		regs.ip	= ctl->parasite_ip;
		jerr(ptrace(PTRACE_SETREGS, ctl->pid, NULL, &regs), err_restore);

		if (ptrace_poke_area((long)ctl->pid, (void *)parasite_arg.args,
				 (void *)ctl->addr_args, parasite_arg.args_size)) {
			pr_err("Can't setup parasite arguments (pid: %d)\n", ctl->pid);
			goto err_restore;
		}

		jerr(ptrace(PTRACE_CONT, (long)ctl->pid, NULL, NULL), err_restore);
		jerr(wait4((long)ctl->pid, &status, __WALL, NULL) != (long)ctl->pid, err_restore);
		jerr(!WIFSTOPPED(status), err_restore);
		jerr(ptrace(PTRACE_GETSIGINFO, (long)ctl->pid, NULL, &siginfo), err_restore);

		if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != SI_KERNEL) {
retry_signal:
			/* pr_debug("** delivering signal %d si_code=%d\n",
				 siginfo.si_signo, siginfo.si_code); */
			/* FIXME: jerr(siginfo.si_code > 0, err_restore_full); */
			jerr(ptrace(PTRACE_SETREGS, (long)ctl->pid, NULL, (void *)&regs_orig), err_restore);
			jerr(ptrace(PTRACE_INTERRUPT, (long)ctl->pid, NULL, NULL), err_restore);
			jerr(ptrace(PTRACE_CONT, (long)ctl->pid, NULL, (void *)(unsigned long)siginfo.si_signo), err_restore);

			jerr(wait4((long)ctl->pid, &status, __WALL, NULL) != (long)ctl->pid, err_restore);
			jerr(!WIFSTOPPED(status), err_restore);
			jerr(ptrace(PTRACE_GETSIGINFO, (long)ctl->pid, NULL, &siginfo), err_restore);

			if (siginfo.si_code >> 8 != PTRACE_EVENT_STOP)
				goto retry_signal;

			goto again;
		}

		/*
		 * Check if error happened during dumping.
		 */
		if (ptrace_peek_area((long)ctl->pid,
				     (void *)args,
				     (void *)(ctl->addr_args),
				     args_size)) {
			pr_err("Can't get dumper ret code (pid: %d)\n", ctl->pid);
			goto err_restore;
		}
		if (args->ret) {
			pr_panic("Dumping sigactions failed with %li (%li) at %li\n",
				 args->ret,
				 args->sys_ret,
				 args->line);

			goto err_restore;
		}


	/*
	 * Our code is done.
	 */
	jerr(ptrace(PTRACE_INTERRUPT, (long)ctl->pid, NULL, NULL), err_restore);
	jerr(ptrace(PTRACE_CONT, (long)ctl->pid, NULL, NULL), err_restore);

	jerr(wait4((long)ctl->pid, &status, __WALL, NULL) != (long)ctl->pid, err_restore);
	jerr(!WIFSTOPPED(status), err_restore);
	jerr(ptrace(PTRACE_GETSIGINFO, (long)ctl->pid, NULL, &siginfo), err_restore);

	jerr((siginfo.si_code >> 8 != PTRACE_EVENT_STOP), err_restore);

	ret = 0;

err_restore:
	if (ptrace(PTRACE_SETREGS, (long)ctl->pid, NULL, &regs_orig)) {
		pr_panic("Can't restore registers (pid: %d)\n", ctl->pid);
		ret = -1;
	}
err:
	return ret;
}

static int get_socket_name(struct sockaddr_un *saddr, pid_t pid)
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

	sun_len = get_socket_name(&saddr, ctl->pid);

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

static int parasite_prep_file(int type,
		struct parasite_ctl *ctl, struct cr_fdset *fdset)
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

static int parasite_file_cmd(int cmd, int type,
		struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	parasite_status_t args = { };
	int status, ret = -1;

	pr_info("\n");
	pr_info("Dumping sigactions (pid: %d)\n", ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(type, ctl, cr_fdset);
	if (ret < 0)
		goto out;

	ret = parasite_execute(cmd, ctl,
			(parasite_status_t *)&args, sizeof(args));

err:
	fchmod(cr_fdset->fds[type], CR_FD_PERM);
out:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parasite_init(struct parasite_ctl *ctl, pid_t pid)
{
	struct parasite_init_args args = { };
	int ret;

	args.sun_len = get_socket_name(&args.saddr, pid);

	ret = parasite_execute(PARASITE_CMD_INIT, ctl,
			(parasite_status_t *)&args, sizeof(args));
	return ret;
}

static int parasite_set_logfd(struct parasite_ctl *ctl, pid_t pid)
{
	parasite_status_t args = { };
	int ret;

	ret = parasite_send_fd(ctl, get_logfd());
	if (ret)
		return ret;

	ret = parasite_execute(PARASITE_CMD_SET_LOGFD, ctl,
			&args, sizeof(args));
	if (ret < 0)
		return ret;

	return 0;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd(PARASITE_CMD_DUMP_SIGACTS, CR_FD_SIGACT, ctl, cr_fdset);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd(PARASITE_CMD_DUMP_ITIMERS, CR_FD_ITIMERS, ctl, cr_fdset);
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	return parasite_execute(PARASITE_CMD_DUMP_MISC, ctl,
			(parasite_status_t *)misc, sizeof(struct parasite_dump_misc));
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
	user_regs_struct_t regs, regs_orig;
	unsigned long nrpages_dumped = 0;
	struct vma_area *vma_area;
	siginfo_t siginfo;
	int status, ret = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(CR_FD_PAGES, ctl, cr_fdset);
	if (ret < 0)
		goto out;

	ret = parasite_prep_file(CR_FD_PAGES_SHMEM, ctl, cr_fdset);
	if (ret < 0)
		goto out;

	ret = parasite_execute(PARASITE_CMD_DUMPPAGES_INIT, ctl, st, sizeof(*st));
	if (ret < 0) {
		pr_panic("Dumping pages failed with %li (%li) at %li\n",
				parasite_dumppages.status.ret,
				parasite_dumppages.status.sys_ret,
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

		pr_info_vma(vma_area);
		parasite_dumppages.vma_entry = vma_area->vma;

		if (vma_area_is(vma_area, VMA_ANON_PRIVATE) ||
		    vma_area_is(vma_area, VMA_FILE_PRIVATE))
			parasite_dumppages.fd_type = PG_PRIV;
		else if (vma_area_is(vma_area, VMA_ANON_SHARED))
			parasite_dumppages.fd_type = PG_SHARED;
		else {
			pr_warning("Unexpected VMA area found\n");
			continue;
		}

		ret = parasite_execute(PARASITE_CMD_DUMPPAGES, ctl,
					(parasite_status_t *) &parasite_dumppages,
					sizeof(parasite_dumppages));
		if (ret) {
			pr_panic("Dumping pages failed with %li (%li) at %li\n",
				 parasite_dumppages.status.ret,
				 parasite_dumppages.status.sys_ret,
				 parasite_dumppages.status.line);

			goto out;
		}

		pr_info("  (dumped: %16li pages)\n", parasite_dumppages.nrpages_dumped);
		nrpages_dumped += parasite_dumppages.nrpages_dumped;
	}

	parasite_execute(PARASITE_CMD_DUMPPAGES_FINI, ctl, st, sizeof(*st));

	if (write_img(cr_fdset->fds[CR_FD_PAGES], &zero_page_entry))
		goto out;
	if (write_img(cr_fdset->fds[CR_FD_PAGES_SHMEM], &zero_page_entry))
		goto out;

	pr_info("\n");
	pr_info("Summary: %16li pages dumped\n", nrpages_dumped);
	ret = 0;

out:
	fchmod(cr_fdset->fds[CR_FD_PAGES], CR_FD_PERM);
	fchmod(cr_fdset->fds[CR_FD_PAGES_SHMEM], CR_FD_PERM);
	pr_info("----------------------------------------\n");

	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list)
{
	user_regs_struct_t regs, regs_orig;
	struct vma_area *vma_area;
	int ret = -1;
	parasite_status_t args = { };

	ret = parasite_execute(PARASITE_CMD_FINI, ctl,
			&args, sizeof(args));
	if (ret) {
		pr_err("Can't finalize parasite (pid: %d) task\n", ctl->pid);
		goto err;
	}

	jerr(ptrace(PTRACE_GETREGS, ctl->pid, NULL, &regs), err);

	regs_orig = regs;

	vma_area = get_vma_by_ip(vma_area_list, regs.ip);
	if (!vma_area) {
		pr_err("No suitable VMA found to run cure (pid: %d)\n", ctl->pid);
		goto err;
	}

	regs.ip = vma_area->vma.start;

	ret = munmap_seized(ctl->pid, &regs,
			    (void *)ctl->vma_area.vma.start,
			    (size_t)vma_entry_len(&ctl->vma_area.vma));
	if (ret)
		pr_err("munmap_seized failed (pid: %d)\n", ctl->pid);

	if (ptrace(PTRACE_SETREGS, ctl->pid, NULL, &regs_orig)) {
		pr_panic("PTRACE_SETREGS failed (pid: %d)\n", ctl->pid);
		ret = -1;
	}

	free(ctl);
err:
	return ret;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct list_head *vma_area_list)
{
	parasite_status_t args = { };
	user_regs_struct_t regs, regs_orig;
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;
	void *mmaped;
	int ret;

	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	/* Setup control block */
	ctl->pid = pid;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs))
		pr_err_jmp(err_free);

	vma_area = get_vma_by_ip(vma_area_list, regs.ip);
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
			 "bootstrap code (pid: %d)\n", pid);
		goto err_free;
	}

	regs_orig = regs;

	/*
	 * Prepare for in-process syscall.
	 */
	ctl->vma_area.vma.prot	= PROT_READ | PROT_WRITE | PROT_EXEC;
	ctl->vma_area.vma.flags	= MAP_PRIVATE | MAP_ANONYMOUS;

	regs.ip = vma_area->vma.start;

	mmaped = mmap_seized(pid, &regs, NULL, (size_t)parasite_size,
			     (int)ctl->vma_area.vma.prot,
			     (int)ctl->vma_area.vma.flags,
			     (int)-1, (off_t)0);

	if (!mmaped || (long)mmaped < 0) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", pid);
		goto err_restore_regs;
	}

	ctl->parasite_ip		= PARASITE_HEAD_ADDR((unsigned long)mmaped);
	ctl->addr_cmd			= PARASITE_CMD_ADDR((unsigned long)mmaped);
	ctl->addr_args			= PARASITE_ARGS_ADDR((unsigned long)mmaped);

	ctl->vma_area.vma.start	= (u64)mmaped;
	ctl->vma_area.vma.end	= (u64)(mmaped + parasite_size);

	if (ptrace_poke_area(pid, parasite_blob, mmaped, parasite_size)) {
		pr_err("Can't inject parasite blob (pid: %d)\n", pid);
		goto err_munmap_restore;
	}

	jerr(ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig), err_munmap_restore);

	ret = parasite_init(ctl, pid);
	if (ret) {
		pr_err("%d: Can't create a transport socket\n", pid);
		goto err_munmap_restore;
	}

	ret = parasite_set_logfd(ctl, pid);
	if (ret) {
		pr_err("%d: Can't set a logging descriptor\n", pid);
		goto err_munmap_restore;
	}

	return ctl;

err_fini:
	ret = parasite_execute(PARASITE_CMD_FINI, ctl,
				&args, sizeof(args));
	if (ret)
		pr_panic("Can't finalize parasite (pid: %d) task\n", ctl->pid);
err_munmap_restore:
	regs = regs_orig, regs.ip = vma_area->vma.start;
	if (munmap_seized(pid, &regs, mmaped, parasite_size))
		pr_panic("mmap_seized failed (pid: %d)\n", pid);
err_restore_regs:
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig))
		pr_panic("PTRACE_SETREGS failed (pid: %d)\n", pid);
err_free:
	if (ctl)
		free(ctl);
err:
	return NULL;
}

#else /* CONFIG_X86_64 */
# error x86-32 is not yet implemented
#endif /* CONFIG_X86_64 */
