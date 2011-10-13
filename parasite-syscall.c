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

#include "compiler.h"
#include "syscall.h"
#include "types.h"
#include "util.h"

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

void *mmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	user_regs_struct_t params = *regs;
	void *mmaped = NULL;
	int ret;

	params.ax	= (unsigned long)__NR_mmap;	/* mmap		*/
	params.di	= (unsigned long)addr;		/* @addr	*/
	params.si	= (unsigned long)length;	/* @length	*/
	params.dx	= (unsigned long)prot;		/* @prot	*/
	params.r10	= (unsigned long)flags;		/* @flags	*/
	params.r8	= (unsigned long)fd;		/* @fd		*/
	params.r9	= (unsigned long)offset;	/* @offset	*/

	ret = syscall_seized(pid, regs, &params, &params);
	if (ret)
		goto err;
	mmaped = (void *)params.ax;

	/* error code from the kernel space */
	if ((long)mmaped < 0)
		mmaped = NULL;
err:
	return mmaped;
}

int munmap_seized(pid_t pid, user_regs_struct_t *regs,
		  void *addr, size_t length)
{
	user_regs_struct_t params = *regs;
	int ret;

	params.ax	= (unsigned long)__NR_munmap;	/* mmap		*/
	params.di	= (unsigned long)addr;		/* @addr	*/
	params.si	= (unsigned long)length;	/* @length	*/

	ret = syscall_seized(pid, regs, &params, &params);
	if (!ret)
		ret = (int)params.ax;

	return ret;
}

int kill_seized(pid_t pid, user_regs_struct_t *where)
{
	user_regs_struct_t params = *where;
	int ret;

	params.ax	= (unsigned long)__NR_exit;	/* exit		*/
	params.di	= (unsigned long)-1;		/* @error-code	*/

	ret = syscall_seized(pid, where, &params, &params);

	return ret;
}

unsigned long brk_seized(pid_t pid, unsigned long addr)
{
	user_regs_struct_t params, regs_orig;
	unsigned long ret = -1UL;

	jerr(ptrace(PTRACE_GETREGS, pid, NULL, &regs_orig), err);
	params = regs_orig;

	params.ax	= (unsigned long)__NR_brk;	/* brk		*/
	params.di	= (unsigned long)addr;		/* @addr	*/

	ret = syscall_seized(pid, &regs_orig, &params, &params);
	if (!ret)
		ret = (unsigned long)params.ax;
	else
		ret = -1UL;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig))
		pr_panic("Can't restore registers (pid: %d)\n", pid);
err:
	return ret;
}

int syscall_seized(pid_t pid,
		   user_regs_struct_t *where,
		   user_regs_struct_t *params,
		   user_regs_struct_t *result)
{
	user_regs_struct_t regs_orig, regs;
	unsigned long start_ip;
	char saved[sizeof(code_syscall)];
	siginfo_t siginfo;
	int status;
	int ret = -1;

	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));

	start_ip	= (unsigned long)where->ip;

	jerr(ptrace_peek_area(pid, (void *)saved, (void *)start_ip, code_syscall_size), err);
	jerr(ptrace_poke_area(pid, (void *)code_syscall, (void *)start_ip, code_syscall_size), err);

again:
	jerr(ptrace(PTRACE_GETREGS, pid, NULL, &regs), err);
	regs_orig	= regs;

	regs.ip		= start_ip;
	regs.ax		= params->ax;
	regs.di		= params->di;
	regs.si		= params->si;
	regs.dx		= params->dx;
	regs.r10	= params->r10;
	regs.r8		= params->r8;
	regs.r9		= params->r9;
	regs.orig_ax	= -1; /* avoid end-of-syscall processing */

	jerr(ptrace(PTRACE_SETREGS, pid, NULL, &regs), err_restore);

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

	jerr(ptrace(PTRACE_GETREGS, pid, NULL, &regs), err_restore_full);

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != SI_KERNEL) {
retry_signal:
		/* pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code); */
		/* FIXME: jerr(siginfo.si_code > 0, err_restore_full); */
		jerr(ptrace(PTRACE_SETREGS, pid, NULL, (void *)&regs_orig), err_restore_full);
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

	jerr(ptrace(PTRACE_GETREGS, pid, NULL, &regs), err_restore_full);

	ret = 0;
	*result = regs;

err_restore_full:
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig))
		pr_panic("Can't restore registers (pid: %d)\n", pid);

err_restore:
	if (ptrace_poke_area(pid, (void *)saved, (void *)start_ip, code_syscall_size))
		pr_panic("Crap... Can't restore data (pid: %d)\n", pid);
err:
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

/*
 * This routine drives parasite code (been previously injected into a victim
 * process) and tells it to dump pages into the file.
 */
int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset, int fd_type)
{
	parasite_args_cmd_dumppages_t parasite_dumppages	= { };
	parasite_args_t parasite_arg				= { };

	user_regs_struct_t regs, regs_orig;
	unsigned long nrpages_dumped = 0;
	struct vma_area *vma_area;
	siginfo_t siginfo;
	int status, path_len, ret = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", fd_type, ctl->pid);
	pr_info("----------------------------------------\n");

	path_len = strlen(cr_fdset->desc[fd_type].name) + 1;

	if (path_len > sizeof(parasite_dumppages.open_path)) {
		pr_panic("Dumping pages path is too long (%d while %d allowed)\n",
			 path_len, sizeof(parasite_dumppages.open_path));
		goto chmod_err;
	}

	if (fchmod(cr_fdset->desc[fd_type].fd, CR_FD_PERM_DUMP)) {
		pr_perror("Can't change permissions on pages file\n");
		goto chmod_err;
	}

	/*
	 * Make sure the data is on disk since we will re-open
	 * it in another process.
	 */
	fsync(cr_fdset->desc[fd_type].fd);

	jerr(ptrace(PTRACE_GETREGS, ctl->pid, NULL, &regs_orig), err);

	parasite_arg.command		= PARASITE_CMD_DUMPPAGES;
	parasite_arg.args_size		= sizeof(parasite_dumppages);
	parasite_arg.args		= &parasite_dumppages;

	strncpy(parasite_dumppages.open_path, cr_fdset->desc[fd_type].name,
		sizeof(parasite_dumppages.open_path));
	parasite_dumppages.open_flags	= O_WRONLY;
	parasite_dumppages.open_mode	= CR_FD_PERM_DUMP;
	parasite_dumppages.fd		= -1UL;

	/*
	 * Pass the command first, it's immutable.
	 */
	jerr(ptrace_poke_area((long)ctl->pid, (void *)&parasite_arg.command,
			     (void *)ctl->addr_cmd, sizeof(parasite_arg.command)),
			     err_restore);

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

again:
		jerr(ptrace(PTRACE_GETREGS, ctl->pid, NULL, &regs), err_restore);
		regs.ip	= ctl->parasite_ip;
		jerr(ptrace(PTRACE_SETREGS, ctl->pid, NULL, &regs), err_restore);

		parasite_dumppages.vma_entry = vma_area->vma;

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
		 * It's a bit tricky, the file get opened inside
		 * parasite but close via explicit syscall. Better would
		 * be to add some 'status' and close inside parasite on
		 * last call.
		 */
		if (parasite_dumppages.fd == -1UL) {
			if (ptrace_peek_area((long)ctl->pid,
					     (void *)&parasite_dumppages.fd,
					     (void *)(ctl->addr_args +
						      offsetof(parasite_args_cmd_dumppages_t, fd)),
					     sizeof(parasite_dumppages.fd))) {
				pr_err("Can't get file descriptor back (pid: %d)\n", ctl->pid);
				goto err_restore;
			}
		}

		/*
		 * Get some statistics.
		 */
		if (ptrace_peek_area((long)ctl->pid,
				     (void *)&parasite_dumppages.nrpages_dumped,
				     (void *)(ctl->addr_args +
					      offsetof(parasite_args_cmd_dumppages_t, nrpages_dumped)),
				     sizeof(parasite_dumppages.fd))) {
			pr_err("Can't get statistics (pid: %d)\n", ctl->pid);
			goto err_restore;
		}
		pr_info("  (dumped: %16li pages)\n", parasite_dumppages.nrpages_dumped);
		nrpages_dumped += parasite_dumppages.nrpages_dumped;
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

	jerr(ptrace(PTRACE_GETREGS, (long)ctl->pid, NULL, &regs), err_restore);

	ret = 0;

	/* Finally close the descriptor the parasite has opened */
	if (parasite_dumppages.fd != -1UL) {
		regs	= regs_orig;
		regs.ax	= __NR_close;			/* close	*/
		regs.di	= parasite_dumppages.fd;	/* @fd		*/
		ret	= syscall_seized(ctl->pid, &regs_orig, &regs, &regs);
	}

	/*
	 * We don't know the position in file since it's updated
	 * outside of our process.
	 */
	lseek(cr_fdset->desc[CR_FD_PAGES].fd, 0, SEEK_END);

	/* Ending page */
	write_ptr_safe(cr_fdset->desc[CR_FD_PAGES].fd, &zero_page_entry, err_restore);

	pr_info("\n");
	pr_info("Summary: %16li pages dumped\n", nrpages_dumped);

err_restore:
	if (ptrace(PTRACE_SETREGS, (long)ctl->pid, NULL, &regs_orig))
		pr_panic("Can't restore registers (pid: %d)\n", ctl->pid);

err:
	jerr(fchmod(cr_fdset->desc[fd_type].fd, CR_FD_PERM), chmod_err);

chmod_err:
	pr_info("----------------------------------------\n");

	return ret;
}

int parasite_cure_seized(struct parasite_ctl **p_ctl,
			 struct list_head *vma_area_list)
{
	user_regs_struct_t regs, regs_orig;
	struct parasite_ctl *ctl;
	struct vma_area *vma_area;
	int ret = -1;

	if (!p_ctl || !*p_ctl)
		return 0;

	ctl = *p_ctl;

	jerr(ptrace(PTRACE_GETREGS, ctl->pid, NULL, &regs), err);

	regs_orig = regs;

	vma_area = get_vma_by_ip(vma_area_list, regs.ip);
	if (!vma_area) {
		pr_err("No suitable VMA found to run cure (pid: %d)\n", ctl->pid);
		goto err;
	}

	regs.ip = vma_area->vma.start;

	ret = munmap_seized(ctl->pid, &regs,
			    (void *)ctl->vma_area->vma.start,
			    (size_t)vma_entry_len(&ctl->vma_area->vma));
	if (ret)
		pr_err("munmap_seized failed (pid: %d)\n", ctl->pid);

	if (ptrace(PTRACE_SETREGS, ctl->pid, NULL, &regs_orig)) {
		ret = -1;
		pr_panic("PTRACE_SETREGS failed (pid: %d)\n", ctl->pid);
	}

	free(*p_ctl), *p_ctl = NULL;
err:
	return ret;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, void *addr_hint, struct list_head *vma_area_list)
{
	user_regs_struct_t regs, regs_orig;
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;
	void *mmaped;

	ctl = xzalloc(sizeof(*ctl) + sizeof(*vma_area));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	/* Setup control block */
	ctl->pid	= pid;
	ctl->vma_area	= (struct vma_area *)(char *)&ctl[sizeof(*ctl)];

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
	ctl->vma_area->vma.prot		= PROT_READ | PROT_WRITE | PROT_EXEC;
	ctl->vma_area->vma.flags	= MAP_PRIVATE | MAP_ANONYMOUS;

	regs.ip = vma_area->vma.start;

	mmaped = mmap_seized(pid, &regs, addr_hint, (size_t)parasite_size,
			     (int)ctl->vma_area->vma.prot,
			     (int)ctl->vma_area->vma.flags,
			     (int)-1, (off_t)0);

	if (!mmaped || (long)mmaped < 0) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", pid);
		goto err_restore_regs;
	}

	ctl->parasite_ip		= PARASITE_HEAD_ADDR((unsigned long)mmaped);
	ctl->parasite_complete_ip	= PARASITE_COMPLETE_ADDR((unsigned long)mmaped);
	ctl->addr_cmd			= PARASITE_CMD_ADDR((unsigned long)mmaped);
	ctl->addr_args			= PARASITE_ARGS_ADDR((unsigned long)mmaped);

	ctl->vma_area->vma.start= (u64)mmaped;
	ctl->vma_area->vma.end	= (u64)(mmaped + parasite_size);

	if (ptrace_poke_area(pid, parasite_blob, mmaped, parasite_size)) {
		pr_err("Can't inject parasite blob (pid: %d)\n", pid);
		goto err_munmap_restore;
	}

	jerr(ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig), err_munmap_restore);

	return ctl;

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
