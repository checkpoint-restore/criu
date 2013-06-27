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

#include "asm/types.h"
#include "list.h"
#include "namespaces.h"
#include "compiler.h"
#include "crtools.h"
#include "util.h"
#include "sockets.h"
#include "image.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "pstree.h"

#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/ns.pb-c.h"
#include "protobuf/ghost-file.pb-c.h"
#include "protobuf/fifo.pb-c.h"
#include "protobuf/remap-file-path.pb-c.h"
#include "protobuf/fown.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/pstree.pb-c.h"
#include "protobuf/pipe.pb-c.h"
#include "protobuf/pipe-data.pb-c.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/timer.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/vma.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/tty.pb-c.h"
#include "protobuf/pagemap.pb-c.h"
#include "protobuf/siginfo.pb-c.h"

#define DEF_PAGES_PER_LINE	6


#define PR_SYMBOL(sym)			\
	(isprint(sym) ? sym : '.')

static LIST_HEAD(pstree_list);

void show_files(int fd_files)
{
	pb_show_plain_pretty(fd_files, PB_FDINFO, "flags:%#o fd:%d");
}

void show_fown_cont(void *p)
{
	FownEntry *fown = p;
	pr_msg("fown: uid: %#x euid: %#x signum: %#x pid_type: %#x pid: %u",
	       fown->uid, fown->euid, fown->signum, fown->pid_type, fown->pid);
}

void show_ns_files(int fd)
{
	pb_show_plain(fd, PB_NS_FILES);
}

void show_reg_files(int fd_reg_files)
{
	pb_show_plain(fd_reg_files, PB_REG_FILES);
}

void show_remap_files(int fd)
{
	pb_show_plain(fd, PB_REMAP_FPATH);
}

void show_ghost_file(int fd)
{
	pb_show_vertical(fd, PB_GHOST_FILE);
}

static void pipe_data_handler(int fd, void *obj)
{
	PipeDataEntry *e = obj;
	print_image_data(fd, e->bytes, opts.show_pages_content);
}

void show_pipes_data(int fd)
{
	pb_show_plain_payload(fd, PB_PIPES_DATA, pipe_data_handler);
}

void show_pipes(int fd_pipes)
{
	pb_show_plain(fd_pipes, PB_PIPES);
}

void show_fifo_data(int fd)
{
	show_pipes_data(fd);
}

void show_fifo(int fd)
{
	pb_show_plain(fd, PB_FIFO);
}

void show_tty(int fd)
{
	pb_show_plain(fd, PB_TTY);
}

void show_tty_info(int fd)
{
	pb_show_plain(fd, PB_TTY_INFO);
}

void show_file_locks(int fd)
{
	pb_show_plain(fd, PB_FILE_LOCK);
}

void show_fs(int fd_fs)
{
	pb_show_vertical(fd_fs, PB_FS);
}

void show_vmas(int fd_vma)
{
	pb_show_plain(fd_vma, PB_VMAS);
}

void show_rlimit(int fd)
{
	pb_show_plain(fd, PB_RLIMIT);
}

static int nice_width_for(unsigned long addr)
{
	int ret = 3;

	while (addr) {
		addr >>= 4;
		ret++;
	}

	return ret;
}

void print_data(unsigned long addr, unsigned char *data, size_t size)
{
	int i, j, addr_len;
	unsigned zero_line = 0;

	addr_len = nice_width_for(addr + size);

	for (i = 0; i < size; i += 16) {
		if (*(u64 *)(data + i) == 0 && *(u64 *)(data + i + 8) == 0) {
			if (zero_line == 0)
				zero_line = 1;
			else {
				if (zero_line == 1) {
					pr_msg("*\n");
					zero_line = 2;
				}

				continue;
			}
		} else
			zero_line = 0;

		pr_msg("%#0*lx: ", addr_len, addr + i);
		for (j = 0; j < 8; j++)
			pr_msg("%02x ", data[i +  j]);
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_msg("%02x ", data[i +  j]);

		pr_msg(" |");
		for (j = 0; j < 8; j++)
			pr_msg("%c", PR_SYMBOL(data[i + j]));
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_msg("%c", PR_SYMBOL(data[i + j]));

		pr_msg("|\n");
	}
}

void print_image_data(int fd, unsigned int length, int show)
{
	void *data;
	int ret;

	if (!show) {
		lseek(fd, length, SEEK_CUR);
		return;
	}

	pr_msg("\n");

	data = xmalloc(length);
	if (!data)
		return;
	ret = read_img_buf(fd, (unsigned char *)data, length);
	if (ret < 0) {
		xfree(data);
		return;
	}
	print_data(0, (unsigned char *)data, length);
	xfree(data);
}

static void show_pagemaps(int fd, void *obj)
{
	pb_show_plain_pretty(fd, PB_PAGEMAP, "nr_pages:%u");
}

void show_pagemap(int fd)
{
	do_pb_show_plain(fd, PB_PAGEMAP_HEAD, 1, show_pagemaps, NULL);
}

void show_siginfo(int fd)
{
	int ret;

	pr_img_head(CR_FD_SIGNAL);
	while (1) {
		SiginfoEntry *sie;
		siginfo_t *info;

		ret = pb_read_one_eof(fd, &sie, PB_SIGINFO);
		if (ret <= 0)
			break;

		info = (siginfo_t *) sie->siginfo.data;
		pr_msg("signal: si_signo=%d si_code=%x\n",
				info->si_signo, info->si_code);
		siginfo_entry__free_unpacked(sie, NULL);

	}
	pr_img_tail(CR_FD_SIGNAL);
}

void show_sigacts(int fd_sigacts)
{
	pb_show_plain(fd_sigacts, PB_SIGACT);
}

void show_itimers(int fd)
{
	pb_show_plain_pretty(fd, PB_ITIMERS, "*:%Lu");
}

void show_posix_timers(int fd)
{
	pb_show_plain_pretty(fd, PB_POSIX_TIMERS, "*:%d 5:%Lu 7:%Lu 8:%lu 9:%Lu 10:%Lu");
}

void show_creds(int fd)
{
	pb_show_vertical(fd, PB_CREDS);
}

static int pstree_item_from_pb(PstreeEntry *e, struct pstree_item *item)
{
	int i;

	item->pid.virt = e->pid;
	item->nr_threads = e->n_threads;
	item->threads = xzalloc(sizeof(struct pid) * e->n_threads);
	if (!item->threads)
		return -1;

	for (i = 0; i < item->nr_threads; i++)
		item->threads[i].virt = e->threads[i];

	return 0;
}

static void pstree_handler(int fd, void *obj)
{
	PstreeEntry *e = obj;
	struct pstree_item *item = NULL;

	item = xzalloc(sizeof(struct pstree_item));
	if (!item)
		return;

	if (pstree_item_from_pb(e, item)) {
		xfree(item);
		return;
	}

	list_add_tail(&item->sibling, &pstree_list);
}

void show_collect_pstree(int fd, int collect)
{
	pb_show_plain_payload_pretty(fd, PB_PSTREE,
			collect ? pstree_handler : NULL, "*:%d");
}

void show_pstree(int fd)
{
	show_collect_pstree(fd, 0);
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

static void show_core_regs(UserX86RegsEntry *regs)
{
#define pr_regs4(s, n1, n2, n3, n4)	\
	pr_msg("\t%8s: 0x%-16"PRIx64" "	\
	       "%8s: 0x%-16"PRIx64" "	\
	       "%8s: 0x%-16"PRIx64" "	\
	       "%8s: 0x%-16"PRIx64"\n",	\
	       #n1, s->n1,		\
	       #n2, s->n2,		\
	       #n3, s->n3,		\
	       #n4, s->n4)

#define pr_regs3(s, n1, n2, n3)		\
	pr_msg("\t%8s: 0x%-16"PRIx64" "	\
	       "%8s: 0x%-16"PRIx64" "	\
	       "%8s: 0x%-16"PRIx64"\n",	\
	       #n1, s->n1,		\
	       #n2, s->n2,		\
	       #n3, s->n3)

	pr_msg("\t---[ GP registers set ]---\n");

	pr_regs4(regs, cs, ip, ds, es);
	pr_regs4(regs, ss, sp, fs, gs);
	pr_regs4(regs, di, si, dx, cx);
	pr_regs4(regs, ax, r8, r9, r10);
	pr_regs4(regs, r11, r12, r13, r14);
	pr_regs3(regs, r15, bp, bx);
	pr_regs4(regs, orig_ax, flags, fs_base, gs_base);
	pr_msg("\n");
}

void show_thread_info(ThreadInfoX86 *thread_info)
{
	if (!thread_info)
		return;

	pr_msg("\t---[ Thread info ]---\n");
	pr_msg("\tclear_tid_addr:  0x%"PRIx64"\n", thread_info->clear_tid_addr);
	pr_msg("\n");

	show_core_regs(thread_info->gpregs);
}

void show_core(int fd_core)
{
	pb_show_vertical(fd_core, PB_CORE);
}

void show_ids(int fd_ids)
{
	pb_show_vertical(fd_ids, PB_IDS);
}

void show_mm(int fd_mm)
{
	pb_show_vertical(fd_mm, PB_MM);
}

static struct {
	u32 magic;
	u32 mask;
	char *hint;
} magic_hints[] = {
	{ .magic = 0x45311224, .mask = 0xffffffff, .hint = "ip route dump", },
	{ .magic = 0x47361222, .mask = 0xffffffff, .hint = "ip ifaddr dump", },
	{ .magic = 0x00008b1f, .mask = 0x0000ffff, .hint = "gzip file", },
	{ },
};

static void try_hint_magic(u32 magic)
{
	int i;

	for (i = 0; magic_hints[i].hint != 0; i++)
		if ((magic & magic_hints[i].mask) == magic_hints[i].magic)
			pr_msg("This can be %s\n", magic_hints[i].hint);
}

static int cr_parse_file(void)
{
	u32 magic;
	int fd = -1, ret = -1, i;

	fd = open(opts.show_dump_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", opts.show_dump_file);
		goto err;
	}

	if (read_img(fd, &magic) < 0)
		goto err;

	for (i = 0; i < CR_FD_MAX; i++)
		if (fdset_template[i].magic == magic)
			break;

	if (i == CR_FD_MAX) {
		pr_err("Unknown magic %#x in %s\n",
				magic, opts.show_dump_file);
		try_hint_magic(magic);
		goto err;
	}

	if (!fdset_template[i].show) {
		pr_err("No handler for %#x/%s\n",
				magic, opts.show_dump_file);
		goto err;
	}

	fdset_template[i].show(fd);
	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int cr_show_pstree_item(struct pstree_item *item)
{
	int ret = -1, i;
	struct cr_fdset *cr_fdset = NULL;
	TaskKobjIdsEntry *ids;

	cr_fdset = cr_task_fdset_open(item->pid.virt, O_SHOW);
	if (!cr_fdset)
		goto out;

	pr_msg("Task %d:\n", item->pid.virt);
	pr_msg("----------------------------------------\n");

	show_core(fdset_fd(cr_fdset, CR_FD_CORE));

	if (item->nr_threads > 1) {
		int fd_th;

		for (i = 0; i < item->nr_threads; i++) {

			if (item->threads[i].virt == item->pid.virt)
				continue;

			fd_th = open_image(CR_FD_CORE, O_SHOW, item->threads[i].virt);
			if (fd_th < 0)
				goto outc;

			pr_msg("Thread %d.%d:\n", item->pid.virt, item->threads[i].virt);
			pr_msg("----------------------------------------\n");

			show_core(fd_th);
			close_safe(&fd_th);
		}
	}

	pr_msg("Resources for %d:\n", item->pid.virt);
	pr_msg("----------------------------------------\n");
	for (i = _CR_FD_TASK_FROM + 1; i < _CR_FD_TASK_TO; i++)
		if ((i != CR_FD_CORE) && (i != CR_FD_IDS) &&
				fdset_template[i].show) {
			pr_msg("* ");
			pr_msg(fdset_template[i].fmt, item->pid.virt);
			pr_msg(":\n");
			fdset_template[i].show(fdset_fd(cr_fdset, i));
		}

	if (pb_read_one(fdset_fd(cr_fdset, CR_FD_IDS), &ids, PB_IDS) > 0) {
		i = open_image(CR_FD_FDINFO, O_SHOW, ids->files_id);
		if (i >= 0) {
			pr_msg("* ");
			pr_msg(fdset_template[CR_FD_FDINFO].fmt, ids->files_id);
			pr_msg(":\n");

			show_files(i);
			close(i);
		}

		task_kobj_ids_entry__free_unpacked(ids, NULL);
	}

	pr_msg("---[ end of task %d ]---\n", item->pid.virt);

	ret = 0;
outc:
	close_cr_fdset(&cr_fdset);
out:
	return ret;
}

static int cr_show_pid(int pid)
{
	int fd, ret;
	struct pstree_item item;

	fd = open_image(CR_FD_PSTREE, O_SHOW);
	if (fd < 0)
		return -1;

	while (1) {
		PstreeEntry *pe;

		ret = pb_read_one_eof(fd, &pe, PB_PSTREE);
		if (ret <= 0){
			close(fd);
			return ret;
		}

		if (pe->pid == pid) {
			pstree_item_from_pb(pe, &item);
			pstree_entry__free_unpacked(pe, NULL);
			break;
		}

		pstree_entry__free_unpacked(pe, NULL);
	}

	close(fd);

	return cr_show_pstree_item(&item);
}

static int cr_show_all(void)
{
	struct pstree_item *item = NULL, *tmp;
	int ret = -1, fd, pid;

	fd = open_image(CR_FD_PSTREE, O_SHOW);
	if (fd < 0)
		goto out;
	show_collect_pstree(fd, 1);
	close(fd);

	fd = open_image(CR_FD_SK_QUEUES, O_SHOW);
	if (fd < 0)
		goto out;

	show_sk_queues(fd);
	close(fd);

	pid = list_first_entry(&pstree_list, struct pstree_item, sibling)->pid.virt;
	ret = try_show_namespaces(pid);
	if (ret)
		goto out;

	list_for_each_entry(item, &pstree_list, sibling)
		if (cr_show_pstree_item(item))
			break;

out:
	list_for_each_entry_safe(item, tmp, &pstree_list, sibling) {
		list_del(&item->sibling);
		xfree(item->threads);
		xfree(item);
	}
	return ret;
}

int cr_show(int pid)
{
	if (opts.show_dump_file)
		return cr_parse_file();

	if (pid)
		return cr_show_pid(pid);

	return cr_show_all();
}
