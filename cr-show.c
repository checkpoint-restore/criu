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

static void show_shmem(int fd_shmem)
{
	struct shmem_entry e;

	pr_img_head(CR_FD_SHMEM);

	while (1) {
		int ret;
		
		ret = read_img_eof(fd_shmem, &e);
		if (ret <= 0)
			goto out;
		pr_info("0x%lx-0x%lx id %lu\n", e.start, e.end, e.shmid);
	}

out:
	pr_img_tail(CR_FD_SHMEM);
}

static void show_files(int fd_files)
{
	struct fdinfo_entry e;

	pr_img_head(CR_FD_FDINFO);

	while (1) {
		int ret;
		
		ret = read_img_eof(fd_files, &e);
		if (ret <= 0)
			goto out;

		pr_info("type: %02x len: %02x flags: %4x pos: %8x addr: %16lx id: %s",
				e.type, e.len, e.flags, e.pos, e.addr, e.id);

		if (e.len) {
			int ret = read(fd_files, local_buf, e.len);
			if (ret != e.len) {
				pr_perror("Can't read %d bytes\n", e.len);
				goto out;
			}
			local_buf[e.len] = 0;
			pr_info(" --> %s", local_buf);
		}

		pr_info("\n");
	}

out:
	pr_img_tail(CR_FD_FDINFO);
}

static void show_pipes(int fd_pipes)
{
	struct pipe_entry e;
	int ret;

	pr_img_head(CR_FD_PIPES);

	while (1) {
		int ret;
		
		ret = read_img_eof(fd_pipes, &e);
		if (ret <= 0)
			goto out;
		pr_info("fd: %8lx pipeid: %8lx flags: %8lx bytes: %8lx\n",
			e.fd, e.pipeid, e.flags, e.bytes);
		if (e.bytes)
			lseek(fd_pipes, e.bytes, SEEK_CUR);
	}

out:
	pr_img_tail(CR_FD_PIPES);
}

static void show_vma(int fd_vma)
{
	struct vma_area vma_area = {};
	struct vma_entry ve;

	pr_info("\n\t---[VMA areas]---\n");
	while (1) {
		if (read_img(fd_vma, &ve) < 0)
			break;

		if (final_vma_entry(&ve))
			break;

		/* Simply in a sake of fancy printing */
		vma_area.vma = ve;
		pr_info_vma(&vma_area);
	}
}

static void show_pages(int fd_pages, bool show_content)
{
	pr_img_head(CR_FD_PAGES);

	if (show_content) {
		while (1) {
			struct page_entry e;
			unsigned long addr;
			int i, j;

			if (read_img(fd_pages, &e) < 0)
				break;
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
				if (read_img(fd_pages, &e) < 0)
					goto out;
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
	pr_img_tail(CR_FD_PAGES);
}

static void show_sigacts(int fd_sigacts)
{
	struct sa_entry e;

	pr_img_head(CR_FD_SIGACT);

	while (1) {
		int ret;
		
		ret = read_img_eof(fd_sigacts, &e);
		if (ret <= 0)
			goto out;
		pr_info("sigaction: %016lx mask: %08lx "
			"flags: %016lx restorer: %016lx\n",
			(long)e.sigaction,
			(long)e.mask,
			(long)e.flags,
			(long)e.restorer);
	}

out:
	pr_img_tail(CR_FD_SIGACT);
}

static int show_pstree(int fd_pstree, struct list_head *collect)
{
	struct pstree_entry e;

	pr_img_head(CR_FD_PSTREE);

	while (1) {
		u32 pid;
		int ret;
		struct pstree_item *item = NULL;

		ret = read_img_eof(fd_pstree, &e);
		if (ret <= 0)
			goto out;
		pr_info("pid: %8d nr_children: %8d nr_threads: %8d\n",
			e.pid, e.nr_children, e.nr_threads);

		if (collect) {
			item = xzalloc(sizeof(struct pstree_item));
			if (!item)
				return -1;

			item->pid = e.pid;
			item->nr_threads = e.nr_threads;
			item->threads = xzalloc(sizeof(u32) * e.nr_threads);
			if (!item->threads) {
				xfree(item);
				return -1;
			}

			list_add_tail(&item->list, collect);
		}

		if (e.nr_children) {
			pr_info("\\\n");
			pr_info(" +--- children: ");
			while (e.nr_children--) {
				ret = read_img_eof(fd_pstree, &pid);
				if (ret <= 0)
					goto out;
				pr_info(" %6d", pid);
			}
			pr_info("\n");
		}

		if (e.nr_threads) {
			pr_info("  \\\n");
			pr_info("   --- threads: ");
			while (e.nr_threads--) {
				ret = read_img_eof(fd_pstree, &pid);
				if (ret <= 0)
					goto out;
				pr_info(" %6d", pid);
				if (item)
					item->threads[e.nr_threads] = pid;
			}
			pr_info("\n");
		}

	}

out:
	pr_img_tail(CR_FD_PSTREE);
	return 0;
}

static void show_core_regs(int fd_core)
{
	struct user_regs_entry regs;
	struct desc_struct tls;
	int i;

	pr_info("\n\t---[GP registers set]---\n");

	lseek(fd_core, GET_FILE_OFF(struct core_entry, arch.gpregs), SEEK_SET);

	if (read_img(fd_core, &regs) < 0)
		goto err;

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

static inline char *task_state_str(int state)
{
	switch (state) {
	case TASK_ALIVE:
		return "running/sleeping";
	case TASK_DEAD:
		return "zombie";
	default:
		return "UNKNOWN";
	}
}

static void show_core_rest(int fd_core)
{
	struct task_core_entry tc;
	int i;

	lseek(fd_core, GET_FILE_OFF(struct core_entry, tc), SEEK_SET);
	if (read_img(fd_core, &tc) < 0)
		goto err;

	pr_info("\n\t---[Task parameters]---\n");
	pr_info("\tPersonality:  %x\n", tc.personality);
	pr_info("\tCommand:      %s\n", tc.comm);
	pr_info("\tState:        %d (%s)\n", (int)tc.task_state,
			task_state_str((int)tc.task_state));
	if (tc.task_state == TASK_DEAD)
		pr_info("\t   Exit code: %u\n", (unsigned int)tc.exit_code);
	pr_info("\tBrk:          %lx\n", tc.mm_brk);
	pr_info("\tStart code:   %lx\n", tc.mm_start_code);
	pr_info("\tEnd code:     %lx\n", tc.mm_end_code);
	pr_info("\tStart stack:  %lx\n", tc.mm_start_stack);
	pr_info("\tStart data:   %lx\n", tc.mm_start_data);
	pr_info("\tEnd data:     %lx\n", tc.mm_end_data);
	pr_info("\tStart brk:    %lx\n", tc.mm_start_brk);
	pr_info("\n");

err:
	return;
}

static void show_core(int fd_core, bool show_content)
{
	struct stat stat;
	bool is_thread;

	if (fstat(fd_core, &stat)) {
		pr_perror("Can't get stat on core file\n");
		goto out;
	}

	is_thread = (stat.st_size == GET_FILE_OFF_AFTER(struct core_entry));

	if (is_thread)
		pr_img_head(CR_FD_CORE, " (thread)");
	else
		pr_img_head(CR_FD_CORE);

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
	show_pages(fd_core, show_content);
out:
	pr_img_tail(CR_FD_CORE);
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

	if (read_img(fd, &magic) < 0)
		goto err;

	switch (magic) {
	case FDINFO_MAGIC:
		show_files(fd);
		break;
	case PAGES_MAGIC:
		show_pages(fd, opts->show_pages_content);
		break;
	case CORE_MAGIC:
		show_core(fd, opts->show_pages_content);
		break;
	case SHMEM_MAGIC:
		show_shmem(fd);
		break;
	case PSTREE_MAGIC:
		show_pstree(fd, NULL);
		break;
	case PIPES_MAGIC:
		show_pipes(fd);
		break;
	case SIGACT_MAGIC:
		show_sigacts(fd);
		break;
	case UNIXSK_MAGIC:
		show_unixsk(fd);
		break;
	case INETSK_MAGIC:
		show_inetsk(fd);
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

static int cr_show_all(unsigned long pid, struct cr_options *opts)
{
	struct cr_fdset *cr_fdset = NULL;
	struct pstree_item *item = NULL;
	LIST_HEAD(pstree_list);
	int i, ret = -1;

	cr_fdset = prep_cr_fdset_for_restore(pid, CR_FD_DESC_USE(CR_FD_PSTREE));
	if (!cr_fdset)
		goto out;

	ret = show_pstree(cr_fdset->fds[CR_FD_PSTREE], &pstree_list);
	if (ret)
		goto out;

	close_cr_fdset(&cr_fdset);

	list_for_each_entry(item, &pstree_list, list) {

		cr_fdset = prep_cr_fdset_for_restore(item->pid, CR_FD_DESC_NOPSTREE);
		if (!cr_fdset)
			goto out;

		show_core(cr_fdset->fds[CR_FD_CORE], opts->show_pages_content);

		if (item->nr_threads > 1) {
			struct cr_fdset *cr_fdset_th;
			int i;

			for (i = 0; i < item->nr_threads; i++) {

				if (item->threads[i] == item->pid)
					continue;

				cr_fdset_th = prep_cr_fdset_for_restore(item->threads[i], CR_FD_DESC_CORE);
				if (!cr_fdset_th)
					goto out;

				pr_info("\n");
				pr_info("Thread: %d\n", item->threads[i]);
				pr_info("----------------------------------------\n");

				show_core(cr_fdset_th->fds[CR_FD_CORE], opts->show_pages_content);

				pr_info("----------------------------------------\n");

				close_cr_fdset(&cr_fdset_th);
			}
		}

		show_pipes(cr_fdset->fds[CR_FD_PIPES]);

		show_files(cr_fdset->fds[CR_FD_FDINFO]);

		show_shmem(cr_fdset->fds[CR_FD_SHMEM]);

		show_sigacts(cr_fdset->fds[CR_FD_SIGACT]);

		show_unixsk(cr_fdset->fds[CR_FD_UNIXSK]);

		show_inetsk(cr_fdset->fds[CR_FD_INETSK]);

		close_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}

out:
	free_pstree(&pstree_list);
	close_cr_fdset(&cr_fdset);
	return ret;
}

int cr_show(unsigned long pid, struct cr_options *opts)
{
	if (opts->show_dump_file)
		return cr_parse_file(opts);

	return cr_show_all(pid, opts);
}
