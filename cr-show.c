#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "util.h"

#include "image.h"

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif

#define pr_regs4(s, n1, n2, n3, n4)	\
	pr_info("%8s: %16lx "		\
		"%8s: %16lx "		\
		"%8s: %16lx "		\
		"%8s: %16lx\n",		\
		#n1, s.n1,		\
		#n2, s.n2,		\
		#n3, s.n3,		\
		#n4, s.n4)

#define pr_regs3(s, n1, n2, n3)		\
	pr_info("%8s: %16lx "		\
		"%8s: %16lx "		\
		"%8s: %16lx\n",		\
		#n1, s.n1,		\
		#n2, s.n2,		\
		#n3, s.n3)

static char local_buf[PAGE_SIZE];
static LIST_HEAD(pstree_list);

/* FIXME: same as dump -- unify */
static void free_pstree(void)
{
	struct pstree_item *item, *p;

	list_for_each_entry_safe(item, p, &pstree_list, list) {
		xfree(item->children);
		xfree(item);
	}

	INIT_LIST_HEAD(&pstree_list);
}

static void show_core_regs(struct cr_fdset *cr_fdset)
{
	struct user_regs_entry regs;
	struct desc_struct tls;
	int fd_core, i;

	fd_core = cr_fdset->desc[CR_FD_CORE].fd;
	if (fd_core < 0)
		goto err;

	pr_info("\n\t---[GP registers set]---\n");

	lseek(fd_core, GET_FILE_OFF(struct core_entry, u.arch.gpregs), SEEK_SET);

	read_ptr_safe(fd_core, &regs, err);

	pr_regs4(regs, cs, ip, ds, es);
	pr_regs4(regs, ss, sp, fs, gs);
	pr_regs4(regs, di, si, dx, cx);
	pr_regs4(regs, ax, r8, r9, r10);
	pr_regs4(regs, r11, r12, r13, r14);
	pr_regs3(regs, r15, bp, bx);
	pr_regs4(regs, orig_ax, flags, fs_base, gs_base);

	pr_info("\n\t---[TLS area]---\n");

	lseek(fd_core, GET_FILE_OFF(struct core_entry, u.arch.tls_array), SEEK_SET);

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		read_ptr_safe(fd_core, &tls, err);
		pr_info("tls[%2i] = %x %x\n", i, tls.a, tls.b);
	}

err:
	return;
}

static void show_core_rest(struct cr_fdset *cr_fdset)
{
	int fd_core, i;
	u32 personality;
	char comm[TASK_COMM_LEN];
	u64 mm_brk, mm_start_code, mm_end_code;
	u64 mm_start_data, mm_end_data, mm_start_stack, mm_start_brk;

	fd_core = cr_fdset->desc[CR_FD_CORE].fd;
	if (fd_core < 0)
		goto err;

	lseek(fd_core, GET_FILE_OFF(struct core_entry, task_personality), SEEK_SET);
	read_ptr_safe(fd_core, &personality, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, task_comm), SEEK_SET);
	read_safe(fd_core, comm, TASK_COMM_LEN, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_brk), SEEK_SET);
	read_ptr_safe(fd_core, &mm_brk, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_start_code), SEEK_SET);
	read_ptr_safe(fd_core, &mm_start_code, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_end_code), SEEK_SET);
	read_ptr_safe(fd_core, &mm_end_code, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_start_stack), SEEK_SET);
	read_ptr_safe(fd_core, &mm_start_stack, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_start_data), SEEK_SET);
	read_ptr_safe(fd_core, &mm_start_data, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_end_data), SEEK_SET);
	read_ptr_safe(fd_core, &mm_end_data, err);

	lseek(fd_core, GET_FILE_OFF(struct core_entry, mm_start_brk), SEEK_SET);
	read_ptr_safe(fd_core, &mm_start_brk, err);

	pr_info("Personality:  %x\n", personality);
	pr_info("Command:      %s\n", comm);
	pr_info("Brk:          %lx\n", mm_brk);
	pr_info("Start code:   %lx\n", mm_start_code);
	pr_info("End code:     %lx\n", mm_end_code);
	pr_info("Start stack:  %lx\n", mm_end_code);
	pr_info("Start data:   %lx\n", mm_end_code);
	pr_info("End data:     %lx\n", mm_end_code);
	pr_info("Start brk:    %lx\n", mm_end_code);

err:
	return;
}

static void show_files(struct cr_fdset *cr_fdset)
{
	struct fdinfo_entry e;
	int fd_files, ret;

	pr_info("\n");
	pr_info("CR_FD_FDINFO: %s\n", cr_fdset->desc[CR_FD_FDINFO].name);
	pr_info("----------------------------------------\n");

	fd_files = cr_fdset->desc[CR_FD_FDINFO].fd;

	lseek(fd_files, MAGIC_OFFSET, SEEK_SET);

	while (1) {
		ret = read(fd_files, &e, sizeof(e));
		if (!ret)
			goto err;
		if (ret != sizeof(e)) {
			pr_perror("Can't read fdinfo entry");
			goto err;
		}

		if (e.len) {
			ret = read(fd_files, local_buf, e.len);
			if (ret != e.len) {
				pr_perror("Can't read %d bytes\n", e.len);
				goto err;
			}
			local_buf[e.len] = 0;
			pr_info("type: %02x len: %02x flags: %4x pos: %8x addr: %16lx --> %s\n",
				e.type, e.len, e.flags, e.pos, e.addr, local_buf);
		} else
			pr_info("type: %02x len: %02x flags: %4x pos: %8x addr: %16lx\n",
				e.type, e.len, e.flags, e.pos, e.addr);
	}

err:
	pr_info("----------------------------------------\n");
}

static void show_pipes(struct cr_fdset *cr_fdset)
{
	struct pipe_entry e;
	int fd_pipes, ret;

	pr_info("\n");
	pr_info("CR_FD_PIPES: %s\n", cr_fdset->desc[CR_FD_PIPES].name);
	pr_info("----------------------------------------\n");

	fd_pipes = cr_fdset->desc[CR_FD_PIPES].fd;

	lseek(fd_pipes, MAGIC_OFFSET, SEEK_SET);

	while (1) {
		ret = read(fd_pipes, &e, sizeof(e));
		if (!ret)
			goto err;
		if (ret != sizeof(e)) {
			pr_perror("Can't read pipe entry\n");
			goto err;
		}
		pr_info("fd: %8lx pipeid: %8lx flags: %8lx bytes: %8lx\n",
			e.fd, e.pipeid, e.flags, e.bytes);
		if (e.bytes)
			lseek(fd_pipes, e.bytes, SEEK_CUR);
	}

err:
	pr_info("----------------------------------------\n");
}

static void show_core(struct cr_fdset *cr_fdset)
{
	struct vma_area vma_area = {};
	struct vma_entry ve;
	int fd_core, ret;
	u64 va;

	pr_info("\n");
	pr_info("CR_FD_CORE: %s\n", cr_fdset->desc[CR_FD_CORE].name);
	pr_info("----------------------------------------\n");

	fd_core = cr_fdset->desc[CR_FD_CORE].fd;
	if (fd_core < 0)
		goto out;

	show_core_regs(cr_fdset);
	show_core_rest(cr_fdset);

	lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);

	/*
	 * Start with VMA, then pages.
	 */
	pr_info("\n\t---[VMA areas]---\n");
	while (1) {
		ret = read(fd_core, &ve, sizeof(ve));
		if (!ret)
			break;
		if (ret != sizeof(ve)) {
			pr_perror("Unable to read VMA\n");
			goto out;
		}

		if (is_ending_vma(&ve)) {
			pr_info("\n\t---[Pages]---\n");
			while (1) {
				ret = read(fd_core, &va, sizeof(va));
				if (!ret)
					goto out;
				if (ret != sizeof(va)) {
					pr_perror("Unable to read VA\n");
					goto out;
				}
				if (va == 0)
					goto out;
				pr_info("page va: %16lx\n", va);
				lseek(fd_core, PAGE_SIZE, SEEK_CUR);
			}
		}

		/* Simply in a sake of fancy printing */
		vma_area.vma = ve;
		pr_info_vma(&vma_area);
	}

out:
	pr_info("----------------------------------------\n");
}

static void show_pstree_from_file(int fd, char *name)
{
	int ret;

	pr_info("\n");
	pr_info("CR_FD_PSTREE: %s\n", name);
	pr_info("----------------------------------------\n");

	while (1) {
		struct pstree_entry e;
		unsigned long i;
		u32 child_pid;

		ret = read(fd, &e, sizeof(e));
		if (!ret)
			break;
		if (ret != sizeof(e)) {
			pr_perror("Bad pstree entry");
			break;
		}

		pr_info("Process %d number of children: %d\n",
			e.pid, e.nr_children);

		for (i = 0; i < e.nr_children; i++) {
			ret = read(fd, &child_pid,
				   sizeof(child_pid));
			pr_info(" %d", child_pid);
		}
		if (e.nr_children)
			pr_info("\n");
	}

	pr_info("----------------------------------------\n");
}

static void show_pstree(struct list_head *head, char *name)
{
	struct pstree_item *item;
	int i;

	pr_info("\n");
	pr_info("CR_FD_PSTREE: %s\n", name);
	pr_info("----------------------------------------\n");

	list_for_each_entry(item, head, list) {
		pr_info("Process %d number of children: %d\n",
			item->pid, item->nr_children);
		for (i = 0; i < item->nr_children; i++)
			pr_info(" %d", item->children[i]);
		if (item->nr_children)
			pr_info("\n");
	}

	pr_info("----------------------------------------\n");
}

static int collect_pstree(pid_t pid, struct cr_fdset *cr_fdset)
{
	int fd = cr_fdset->desc[CR_FD_PSTREE].fd;
	struct pstree_item *item = NULL;
	struct pstree_entry e;
	int ret = -1;

	for (;;) {
		size_t size;

		ret = read(fd, &e, sizeof(e));
		if (ret && ret != sizeof(e)) {
			pr_perror("Wrong pstree entry\n");
			goto err;
		}

		if (!ret)
			break;

		item = xmalloc(sizeof(*item));
		if (!item)
			goto err;

		size = sizeof(u32) * e.nr_children;

		item->pid		= e.pid;
		item->nr_children	= e.nr_children;
		item->children		= xmalloc(size);

		if (!item->children) {
			pr_err("No memory for children pids\n");
			goto err;
		}

		ret = read(fd, item->children, size);
		if (ret != size) {
			pr_err("An error in reading children pids\n");
			xfree(item->children);
			goto err;
		}

		list_add_tail(&item->list, &pstree_list);
	}

	item = NULL;
	ret = 0;

err:
	xfree(item);
	return ret;
}

int cr_show(unsigned long pid, struct cr_options *opts)
{
	struct cr_fdset *cr_fdset;
	struct pstree_item *item;
	int i, ret = -1;

	cr_fdset = alloc_cr_fdset(pid);
	if (!cr_fdset)
		goto out;

	ret = prep_cr_fdset_for_restore(cr_fdset, CR_FD_DESC_ALL);
	if (ret)
		goto out;

	ret = collect_pstree(pid, cr_fdset);
	if (ret)
		goto out;

	show_pstree(&pstree_list, cr_fdset->desc[CR_FD_PSTREE].name);

	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);

	list_for_each_entry(item, &pstree_list, list) {

		cr_fdset = alloc_cr_fdset(item->pid);
		if (!cr_fdset)
			goto out;

		ret = prep_cr_fdset_for_restore(cr_fdset, CR_FD_DESC_NOPSTREE);
		if (ret)
			goto out;

		show_core(cr_fdset);
		show_pipes(cr_fdset);
		show_files(cr_fdset);

		if (opts->leader_only)
			break;
	}

out:
	free_pstree();
	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);
	return ret;
}
