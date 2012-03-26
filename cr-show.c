#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "types.h"
#include "list.h"
#include "namespaces.h"
#include "compiler.h"
#include "crtools.h"
#include "util.h"
#include "sockets.h"
#include "image.h"
#include "uts_ns.h"
#include "ipc_ns.h"

#define DEF_PAGES_PER_LINE	6

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif


#define PR_SYMBOL(sym)			\
	(isprint(sym) ? sym : '.')

#define pr_regs4(s, n1, n2, n3, n4)	\
	pr_msg("%8s: %16lx "		\
	       "%8s: %16lx "		\
	       "%8s: %16lx "		\
	       "%8s: %16lx\n",		\
	       #n1, s.n1,		\
	       #n2, s.n2,		\
	       #n3, s.n3,		\
	       #n4, s.n4)

#define pr_regs3(s, n1, n2, n3)		\
	pr_msg("%8s: %16lx "		\
	       "%8s: %16lx "		\
	       "%8s: %16lx\n",		\
	       #n1, s.n1,		\
	       #n2, s.n2,		\
	       #n3, s.n3)

static char local_buf[PAGE_SIZE];
static LIST_HEAD(pstree_list);

static char *fdtype2s(u8 type)
{
	static char und[4];
	static char *fdtypes[] = {
		[FDINFO_REG] = "reg",
		[FDINFO_MAP] = "map",
		[FDINFO_CWD] = "cwd",
		[FDINFO_EXE] = "exe",
	};

	if (type > FDINFO_UND && type < FD_INFO_MAX)
		return fdtypes[type];
	snprintf(und, sizeof(und), "x%02d\n", (int)type);
	return und;
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

		pr_msg("type: %s addr: %16lx id: %8x",
		       fdtype2s(e.type), e.addr, e.id);

		pr_msg("\n");
	}

out:
	pr_img_tail(CR_FD_FDINFO);
}

static void show_reg_files(int fd_reg_files)
{
	struct reg_file_entry rfe;

	pr_img_head(CR_FD_REG_FILES);

	while (1) {
		int ret;

		ret = read_img_eof(fd_reg_files, &rfe);
		if (ret <= 0)
			goto out;

		pr_msg("id: %8x flags: %4x pos: %lx", rfe.id, rfe.flags, rfe.pos);

		if (rfe.len) {
			int ret = read(fd_reg_files, local_buf, rfe.len);
			if (ret != rfe.len) {
				pr_perror("Can't read %d bytes", rfe.len);
				goto out;
			}
			local_buf[rfe.len] = 0;
			pr_msg(" --> %s", local_buf);
		}

		pr_msg("\n");
	}

out:
	pr_img_tail(CR_FD_REG_FILES);
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
		pr_msg("fd: %8x pipeid: %8x flags: %8x bytes: %8x\n",
		       e.fd, e.pipeid, e.flags, e.bytes);
		if (e.bytes)
			lseek(fd_pipes, e.bytes, SEEK_CUR);
	}

out:
	pr_img_tail(CR_FD_PIPES);
}

static void show_vmas(int fd_vma)
{
	struct vma_area vma_area = {};
	struct vma_entry ve;

	pr_img_head(CR_FD_VMAS);

	while (1) {
		int ret;

		ret = read_img_eof(fd_vma, &ve);
		if (ret <= 0)
			break;

		/* Simply in a sake of fancy printing */
		vma_area.vma = ve;
		pr_msg_vma(&vma_area);
	}

	pr_img_tail(CR_FD_VMAS);
}

void print_data(unsigned long addr, unsigned char *data, size_t size)
{
	int i, j;

	for (i = 0; i < size; i+= 16) {
		pr_msg("%16lx: ", addr + i);
		for (j = 0; j < 8; j++)
			pr_msg("%02x ", data[i +  j]);
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_msg("%02x ", data[i +  j]);

		pr_msg(" |");
		for (j = 0; j < 8; j++)
			pr_msg("%c ", PR_SYMBOL(data[i + j]));
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_msg("%c ", PR_SYMBOL(data[i + j]));

		pr_msg("|\n");
	}
}

static void show_pages(int fd_pages, bool show_content)
{
	pr_img_head(CR_FD_PAGES);

	if (show_content) {
		while (1) {
			struct page_entry e;

			if (read_img(fd_pages, &e) < 0)
				break;
			if (final_page_entry(&e))
				break;

			print_data(e.va, e.data, PAGE_IMAGE_SIZE);
			pr_msg("\n                  --- End of page ---\n\n");
		}
	} else {
		while (1) {
			struct page_entry e;
			int i, j;

			pr_msg("\t");
			for (i = 0; i < DEF_PAGES_PER_LINE; i++) {
				if (read_img(fd_pages, &e) < 0)
					goto out;
				if (final_page_entry(&e)) {
					pr_msg("\n");
					goto out;
				}
				pr_msg("%16lx ", e.va);
			}
			pr_msg("\n");
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
		pr_msg("sigaction: %016lx mask: %08lx "
		       "flags: %016lx restorer: %016lx\n",
		       (long)e.sigaction,
		       (long)e.mask,
		       (long)e.flags,
		       (long)e.restorer);
	}

out:
	pr_img_tail(CR_FD_SIGACT);
}

static void show_itimer(char *n, struct itimer_entry *ie)
{
	pr_msg("%s: int %lu.%lu val %lu.%lu\n", n,
	       (unsigned long)ie->isec, (unsigned long)ie->iusec,
	       (unsigned long)ie->vsec, (unsigned long)ie->vusec);
}

static void show_itimers(int fd)
{
	struct itimer_entry ie[3];

	pr_img_head(CR_FD_ITIMERS);
	if (read_img_buf(fd, ie, sizeof(ie)) < 0)
		goto out;

	show_itimer("real", &ie[0]);
	show_itimer("virt", &ie[1]);
	show_itimer("prof", &ie[2]);
out:
	pr_img_tail(CR_FD_ITIMERS);
}

static void show_cap(char *name, u32 *v)
{
	int i;

	pr_msg("%s: ", name);
	for (i = CR_CAP_SIZE - 1; i >= 0; i--)
		pr_msg("%08x", v[i]);
	pr_msg("\n");
}

static void show_creds(int fd)
{
	struct creds_entry ce;

	pr_img_head(CR_FD_CREDS);
	if (read_img(fd, &ce) < 0)
		goto out;

	pr_msg("uid %u  euid %u  suid %u  fsuid %u\n",
	       ce.uid, ce.euid, ce.suid, ce.fsuid);
	pr_msg("gid %u  egid %u  sgid %u  fsgid %u\n",
	       ce.gid, ce.egid, ce.sgid, ce.fsgid);

	show_cap("Inh", ce.cap_inh);
	show_cap("Eff", ce.cap_eff);
	show_cap("Prm", ce.cap_prm);
	show_cap("Bnd", ce.cap_bnd);

	pr_msg("secbits: %x\n", ce.secbits);
out:
	pr_img_tail(CR_FD_CREDS);
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
		pr_msg("pid: %8d nr_children: %8d nr_threads: %8d\n",
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
			pr_msg("\\\n");
			pr_msg(" +--- children: ");
			while (e.nr_children--) {
				ret = read_img_eof(fd_pstree, &pid);
				if (ret <= 0)
					goto out;
				pr_msg(" %6d", pid);
			}
			pr_msg("\n");
		}

		if (e.nr_threads) {
			pr_msg("  \\\n");
			pr_msg("   --- threads: ");
			while (e.nr_threads--) {
				ret = read_img_eof(fd_pstree, &pid);
				if (ret <= 0)
					goto out;
				pr_msg(" %6d", pid);
				if (item)
					item->threads[e.nr_threads] = pid;
			}
			pr_msg("\n");
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

	pr_msg("\n\t---[GP registers set]---\n");

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
	pr_msg("\n");

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

	pr_msg("\n\t---[Task parameters]---\n");
	pr_msg("\tPersonality:  %x\n", tc.personality);
	pr_msg("\tCommand:      %s\n", tc.comm);
	pr_msg("\tState:        %d (%s)\n",
	       (int)tc.task_state,
	       task_state_str((int)tc.task_state));

	pr_msg("\t   Exit code: %u\n",
	       (unsigned int)tc.exit_code);

	pr_msg("\tBrk:          %lx\n", tc.mm_brk);
	pr_msg("\tStart code:   %lx\n", tc.mm_start_code);
	pr_msg("\tEnd code:     %lx\n", tc.mm_end_code);
	pr_msg("\tStart stack:  %lx\n", tc.mm_start_stack);
	pr_msg("\tStart data:   %lx\n", tc.mm_start_data);
	pr_msg("\tEnd data:     %lx\n", tc.mm_end_data);
	pr_msg("\tStart brk:    %lx\n", tc.mm_start_brk);
	pr_msg("\tArg start:    %lx\n", tc.mm_arg_start);
	pr_msg("\tArg end:      %lx\n", tc.mm_arg_end);
	pr_msg("\tEnv start:    %lx\n", tc.mm_env_start);
	pr_msg("\tEnv end:      %lx\n", tc.mm_env_end);
	pr_msg("\n\tBlkSig: %lx\n", tc.blk_sigset);
	pr_msg("\n");

err:
	return;
}

static void show_core(int fd_core, bool show_content)
{
	struct stat stat;
	bool is_thread;

	if (fstat(fd_core, &stat)) {
		pr_perror("Can't get stat on core file");
		goto out;
	}

	is_thread = (stat.st_size == GET_FILE_OFF_AFTER(struct core_entry));

	if (is_thread)
		pr_img_head(CR_FD_CORE, " (thread)");
	else
		pr_img_head(CR_FD_CORE);

	show_core_regs(fd_core);
	show_core_rest(fd_core);
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
		pr_perror("Can't open %s", opts->show_dump_file);
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
	case VMAS_MAGIC:
		show_vmas(fd);
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
	case SK_QUEUES_MAGIC:
		show_sk_queues(fd);
		break;
	case ITIMERS_MAGIC:
		show_itimers(fd);
		break;
	case UTSNS_MAGIC:
		show_utsns(fd);
		break;
	case CREDS_MAGIC:
		show_creds(fd);
		break;
	case IPCNS_VAR_MAGIC:
		show_ipc_var(fd);
		break;
	case IPCNS_SHM_MAGIC:
		show_ipc_shm(fd);
		break;
	case IPCNS_MSG_MAGIC:
		show_ipc_msg(fd);
		break;
	case IPCNS_SEM_MAGIC:
		show_ipc_sem(fd);
		break;
	case REG_FILES_MAGIC:
		show_reg_files(fd);
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
	struct pstree_item *item = NULL;
	LIST_HEAD(pstree_list);
	int i, ret = -1, fd;

	fd = open_image_ro(CR_FD_PSTREE);
	if (fd < 0)
		goto out;

	ret = show_pstree(fd, &pstree_list);
	if (ret)
		goto out;

	close(fd);

	fd = open_image_ro(CR_FD_SK_QUEUES);
	if (fd < 0)
		goto out;

	ret = show_sk_queues(fd);
	if (ret)
		goto out;

	close(fd);

	ret = try_show_namespaces(pid);
	if (ret)
		goto out;

	list_for_each_entry(item, &pstree_list, list) {
		struct cr_fdset *cr_fdset = NULL;

		cr_fdset = cr_task_fdset_open(item->pid, O_SHOW);
		if (!cr_fdset)
			goto out;

		show_core(fdset_fd(cr_fdset, CR_FD_CORE), opts->show_pages_content);

		if (item->nr_threads > 1) {
			int i, fd_th;

			for (i = 0; i < item->nr_threads; i++) {

				if (item->threads[i] == item->pid)
					continue;

				fd_th = open_image_ro(CR_FD_CORE, item->threads[i]);
				if (fd_th < 0)
					goto out;

				pr_msg("\n");
				pr_msg("Thread: %d\n", item->threads[i]);
				pr_msg("----------------------------------------\n");

				show_core(fd_th, opts->show_pages_content);

				pr_msg("----------------------------------------\n");

			}
		}

		show_vmas(fdset_fd(cr_fdset, CR_FD_VMAS));

		show_pipes(fdset_fd(cr_fdset, CR_FD_PIPES));

		show_files(fdset_fd(cr_fdset, CR_FD_FDINFO));

		show_sigacts(fdset_fd(cr_fdset, CR_FD_SIGACT));

		show_unixsk(fdset_fd(cr_fdset, CR_FD_UNIXSK));

		show_inetsk(fdset_fd(cr_fdset, CR_FD_INETSK));

		show_itimers(fdset_fd(cr_fdset, CR_FD_ITIMERS));

		show_creds(fdset_fd(cr_fdset, CR_FD_CREDS));

		close_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}

out:
	free_pstree(&pstree_list);
	return ret;
}

int cr_show(unsigned long pid, struct cr_options *opts)
{
	if (opts->show_dump_file)
		return cr_parse_file(opts);

	return cr_show_all(pid, opts);
}
