#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "util.h"
#include "sockets.h"
#include "image.h"

#define DEF_PAGES_PER_LINE	6

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif


#define PR_SYMBOL(sym)				\
	((sym < 32 || sym > 126) ? '.' : sym)

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

static void show_shmem(char *name, int fd_shmem, bool show_header)
{
	struct shmem_entry e;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_SHMEM: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	while (1) {
		int ret = read_ptr_safe_eof(fd_shmem, &e, out);
		if (!ret)
			goto out;
		pr_info("0x%lx-0x%lx id %lu\n", e.start, e.end, e.shmid);
	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_files(char *name, int fd_files, bool show_header)
{
	struct fdinfo_entry e;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_FDINFO: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	while (1) {
		int ret = read_ptr_safe_eof(fd_files, &e, out);
		if (!ret)
			goto out;
		if (e.len) {
			int ret = read(fd_files, local_buf, e.len);
			if (ret != e.len) {
				pr_perror("Can't read %d bytes\n", e.len);
				goto out;
			}
			local_buf[e.len] = 0;
			pr_info("type: %02x len: %02x flags: %4x pos: %8x addr: %16lx --> %s\n",
				e.type, e.len, e.flags, e.pos, e.addr, local_buf);
		} else
			pr_info("type: %02x len: %02x flags: %4x pos: %8x addr: %16lx\n",
				e.type, e.len, e.flags, e.pos, e.addr);
	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_pipes(char *name, int fd_pipes, bool show_header)
{
	struct pipe_entry e;
	int ret;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_PIPES: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	while (1) {
		int ret = read_ptr_safe_eof(fd_pipes, &e, out);
		if (!ret)
			goto out;
		pr_info("fd: %8lx pipeid: %8lx flags: %8lx bytes: %8lx\n",
			e.fd, e.pipeid, e.flags, e.bytes);
		if (e.bytes)
			lseek(fd_pipes, e.bytes, SEEK_CUR);
	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_vma(int fd_vma)
{
	struct vma_area vma_area = {};
	struct vma_entry ve;

	pr_info("\n\t---[VMA areas]---\n");
	while (1) {
		read_ptr_safe(fd_vma, &ve, out);

		if (final_vma_entry(&ve))
			break;

		/* Simply in a sake of fancy printing */
		vma_area.vma = ve;
		pr_info_vma(&vma_area);
	}
out:
	; /* to placate gcc */
}

static void show_pages(char *name, int fd_pages, bool show_header, bool show_content)
{
	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_PAGES: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	if (show_content) {
		while (1) {
			struct page_entry e;
			unsigned long addr;
			int i, j;

			read_ptr_safe(fd_pages, &e, out);
			if (final_page_entry(&e))
				break;

			addr = e.va;
			for (i = 0; i < PAGE_IMAGE_SIZE; i+= 16) {
				pr_info("%16lx: ", addr + i);
				for (j = 0; j < 8; j++)
					pr_info("%02x ", e.data[i +  j]);
				pr_info(" ");
				for (j = 8; j < 16; j++)
					pr_info("%02x ", e.data[i +  j]);

				pr_info(" |");
				for (j = 0; j < 8; j++)
					pr_info("%c ", PR_SYMBOL(e.data[i + j]));
				pr_info(" ");
				for (j = 8; j < 16; j++)
					pr_info("%c ", PR_SYMBOL(e.data[i + j]));

				pr_info("|\n");
			}
			pr_info("\n                  --- End of page ---\n\n");
		}
	} else {
		while (1) {
			struct page_entry e;
			int i, j;

			pr_info("\t");
			for (i = 0; i < DEF_PAGES_PER_LINE; i++) {
				read_ptr_safe(fd_pages, &e, out);
				if (final_page_entry(&e)) {
					pr_info("\n");
					goto out;
				}
				pr_info("%16lx ", e.va);
			}
			pr_info("\n");
		}
	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_sigacts(char *name, int fd_sigacts, bool show_header)
{
	struct sa_entry e;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_SIGACT: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	while (1) {
		int ret = read_ptr_safe_eof(fd_sigacts, &e, out);
		if (!ret)
			goto out;
		pr_info("sigaction: %016lx mask: %08lx "
			"flags: %016lx restorer: %016lx\n",
			(long)e.sigaction,
			(long)e.mask,
			(long)e.flags,
			(long)e.restorer);
	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_pstree(char *name, int fd_sigacts, bool show_header)
{
	struct pstree_entry e;

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_PSTREE: %s\n", name);
		pr_info("----------------------------------------\n");
	}

	while (1) {
		u32 pid;
		int ret;

		ret = read_ptr_safe_eof(fd_sigacts, &e, out);
		if (!ret)
			goto out;
		pr_info("pid: %8d nr_children: %8d nr_threads: %8d\n",
			e.pid, e.nr_children, e.nr_threads);

		if (e.nr_children) {
			pr_info("\\\n");
			pr_info(" +--- children: ");
			while (e.nr_children--) {
				ret = read_ptr_safe_eof(fd_sigacts, &pid, out);
				if (!ret)
					goto out;
				pr_info(" %6d", pid);
			}
			pr_info("\n");
		}

		if (e.nr_threads) {
			pr_info("  \\\n");
			pr_info("   --- threads: ");
			while (e.nr_threads--) {
				ret = read_ptr_safe_eof(fd_sigacts, &pid, out);
				if (!ret)
					goto out;
				pr_info(" %6d", pid);
			}
			pr_info("\n");
		}

	}

out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static void show_core_regs(int fd_core)
{
	struct user_regs_entry regs;
	struct desc_struct tls;
	int i;

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
	pr_info("\n");

err:
	return;
}

static void show_core_rest(int fd_core)
{
	u64 mm_start_data, mm_end_data, mm_start_stack, mm_start_brk;
	u64 mm_brk, mm_start_code, mm_end_code;
	char comm[TASK_COMM_LEN];
	u32 personality;
	int i;

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

	pr_info("\n\t---[Task parameters]---\n");
	pr_info("\tPersonality:  %x\n", personality);
	pr_info("\tCommand:      %s\n", comm);
	pr_info("\tBrk:          %lx\n", mm_brk);
	pr_info("\tStart code:   %lx\n", mm_start_code);
	pr_info("\tEnd code:     %lx\n", mm_end_code);
	pr_info("\tStart stack:  %lx\n", mm_start_stack);
	pr_info("\tStart data:   %lx\n", mm_start_data);
	pr_info("\tEnd data:     %lx\n", mm_end_data);
	pr_info("\tStart brk:    %lx\n", mm_start_brk);
	pr_info("\n");

err:
	return;
}

static void show_core(char *name, int fd_core, bool show_header, bool show_content)
{
	struct stat stat;
	bool is_thread;

	if (fstat(fd_core, &stat)) {
		pr_perror("Can't get stat on %s\n", name);
		goto out;
	}

	is_thread = (stat.st_size == GET_FILE_OFF_AFTER(struct core_entry));

	if (show_header) {
		pr_info("\n");
		pr_info("CR_FD_CORE: %s", name);
		if (is_thread)
			pr_info(" (thread)\n");
		else
			pr_info("\n");
		pr_info("----------------------------------------\n");
	}

	show_core_regs(fd_core);
	show_core_rest(fd_core);
	if (is_thread)
		goto out;

	lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	/*
	 * If this is thread code -- we should jump out once
	 * we reach EOF.
	 */
	if (is_thread)
		goto out;

	show_vma(fd_core);

	pr_info("\n\t---[Memory pages]---\n");
	show_pages(name, fd_core, false, show_content);
out:
	if (show_header)
		pr_info("----------------------------------------\n");
}

static int cr_parse_file(struct cr_options *opts)
{
	u32 magic;
	int fd = -1;
	int ret = -1;

	fd = open(opts->show_dump_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s\n", opts->show_dump_file);
		goto err;
	}

	read_ptr_safe(fd, &magic, err);

	switch (magic) {
	case FDINFO_MAGIC:
		show_files(opts->show_dump_file, fd, true);
		break;
	case PAGES_MAGIC:
		show_pages(opts->show_dump_file, fd, true,
			   opts->show_pages_content);
		break;
	case CORE_MAGIC:
		show_core(opts->show_dump_file, fd, true,
			  opts->show_pages_content);
		break;
	case SHMEM_MAGIC:
		show_shmem(opts->show_dump_file, fd, true);
		break;
	case PSTREE_MAGIC:
		show_pstree(opts->show_dump_file, fd, true);
		break;
	case PIPES_MAGIC:
		show_pipes(opts->show_dump_file, fd, true);
		break;
	case SIGACT_MAGIC:
		show_sigacts(opts->show_dump_file, fd, true);
		break;
	case UNIXSK_MAGIC:
		show_unixsk(opts->show_dump_file, fd, true);
		break;
	default:
		pr_err("Unknown magic %x on %s\n", magic, opts->show_dump_file);
		goto err;
	}
	ret = 0;

err:
	close_safe(&fd);
	return ret;
}

static int collect_pstree(struct list_head *head, pid_t pid, struct cr_fdset *cr_fdset)
{
	int fd = cr_fdset->desc[CR_FD_PSTREE].fd;
	struct pstree_item *item = NULL;
	struct pstree_entry e;
	int ret = -1;

	for (;;) {
		size_t size_children, size_threads;

		ret = read(fd, &e, sizeof(e));
		if (ret && ret != sizeof(e)) {
			pr_perror("Wrong pstree entry\n");
			goto err;
		}

		if (!ret)
			break;

		item = xzalloc(sizeof(*item));
		if (!item)
			goto err;

		size_children	= sizeof(u32) * e.nr_children;
		size_threads	= sizeof(u32) * e.nr_threads;

		item->pid		= e.pid;
		item->nr_children	= e.nr_children;
		item->nr_threads	= e.nr_threads;
		item->children		= xmalloc(size_children);
		item->threads		= xmalloc(size_threads);

		if (!item->children || !item->threads) {
			pr_err("No memory for children/thread pids\n");
			goto err;
		}

		ret = read(fd, item->children, size_children);
		if (ret != size_children) {
			pr_err("An error in reading children pids\n");
			goto err;
		}

		ret = read(fd, item->threads, size_threads);
		if (ret != size_threads) {
			pr_err("An error in reading threads pids\n");
			goto err;
		}

		list_add_tail(&item->list, head);
	}

	item = NULL;
	ret = 0;

err:
	if (item) {
		xfree(item->children);
		xfree(item->threads);
	}
	xfree(item);

	return ret;
}

static int cr_show_all(unsigned long pid, struct cr_options *opts)
{
	struct cr_fdset *cr_fdset = NULL;
	struct pstree_item *item = NULL;
	LIST_HEAD(pstree_list);
	int i, ret = -1;

	cr_fdset = alloc_cr_fdset(pid);
	if (!cr_fdset)
		goto out;

	ret = prep_cr_fdset_for_restore(cr_fdset,
					CR_FD_DESC_USE(CR_FD_PSTREE));
	if (ret)
		goto out;

	ret = collect_pstree(&pstree_list, pid, cr_fdset);
	if (ret)
		goto out;

	/*
	 * Yeah, I know we read the same file for second
	 * time here, but this saves us from code duplication.
	 */
	lseek(cr_fdset->desc[CR_FD_PSTREE].fd, MAGIC_OFFSET, SEEK_SET);
	show_pstree(cr_fdset->desc[CR_FD_PSTREE].path,
		    cr_fdset->desc[CR_FD_PSTREE].fd,
		    true);

	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);

	list_for_each_entry(item, &pstree_list, list) {

		cr_fdset = alloc_cr_fdset(item->pid);
		if (!cr_fdset)
			goto out;

		ret = prep_cr_fdset_for_restore(cr_fdset, CR_FD_DESC_NOPSTREE);
		if (ret)
			goto out;

		lseek(cr_fdset->desc[CR_FD_CORE].fd, MAGIC_OFFSET, SEEK_SET);
		show_core(cr_fdset->desc[CR_FD_CORE].path,
			  cr_fdset->desc[CR_FD_CORE].fd,
			  true, opts->show_pages_content);

		if (item->nr_threads > 1) {
			struct cr_fdset *cr_fdset_th;
			int i;

			for (i = 0; i < item->nr_threads; i++) {

				if (item->threads[i] == item->pid)
					continue;

				cr_fdset_th = alloc_cr_fdset(item->threads[i]);
				if (!cr_fdset)
					goto out;

				ret = prep_cr_fdset_for_restore(cr_fdset_th, CR_FD_DESC_CORE);
				if (ret)
					goto out;

				pr_info("\n");
				pr_info("Thread: %d\n", item->threads[i]);
				pr_info("----------------------------------------\n");

				lseek(cr_fdset_th->desc[CR_FD_CORE].fd, MAGIC_OFFSET, SEEK_SET);
				show_core(cr_fdset_th->desc[CR_FD_CORE].path,
					  cr_fdset_th->desc[CR_FD_CORE].fd,
					  false, opts->show_pages_content);

				pr_info("----------------------------------------\n");

				close_cr_fdset(cr_fdset_th);
				free_cr_fdset(&cr_fdset_th);
			}
		}

		show_pipes(cr_fdset->desc[CR_FD_PIPES].path,
			   cr_fdset->desc[CR_FD_PIPES].fd, true);

		show_files(cr_fdset->desc[CR_FD_FDINFO].path,
			   cr_fdset->desc[CR_FD_FDINFO].fd, true);

		show_shmem(cr_fdset->desc[CR_FD_SHMEM].path,
			   cr_fdset->desc[CR_FD_SHMEM].fd, true);

		show_sigacts(cr_fdset->desc[CR_FD_SIGACT].path,
			     cr_fdset->desc[CR_FD_SIGACT].fd, true);

		show_unixsk(cr_fdset->desc[CR_FD_UNIXSK].path,
				cr_fdset->desc[CR_FD_UNIXSK].fd, true);

		close_cr_fdset(cr_fdset);
		free_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}

out:
	free_pstree(&pstree_list);
	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);
	return ret;
}

int cr_show(unsigned long pid, struct cr_options *opts)
{
	if (opts->show_single_file)
		return cr_parse_file(opts);

	return cr_show_all(pid, opts);
}
