#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>

#include <fcntl.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>
#include <sys/prctl.h>

#include <sched.h>

#include <sys/sendfile.h>

#include "ptrace.h"
#include "compiler.h"
#include "asm/types.h"
#include "asm/restorer.h"

#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "util.h"
#include "util-pie.h"
#include "log.h"
#include "restorer.h"
#include "sockets.h"
#include "sk-packet.h"
#include "lock.h"
#include "files.h"
#include "files-reg.h"
#include "pipes.h"
#include "fifo.h"
#include "sk-inet.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "signalfd.h"
#include "proc_parse.h"
#include "restorer-blob.h"
#include "crtools.h"
#include "namespaces.h"
#include "mem.h"
#include "mount.h"
#include "fsnotify.h"
#include "pstree.h"
#include "net.h"
#include "tty.h"
#include "cpu.h"
#include "file-lock.h"
#include "page-read.h"
#include "vdso.h"
#include "stats.h"
#include "tun.h"
#include "vma.h"
#include "kerndat.h"
#include "rst-malloc.h"
#include "plugin.h"
#include "cgroup.h"
#include "timerfd.h"
#include "file-lock.h"
#include "action-scripts.h"
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "bitmap.h"
#include "fault-injection.h"
#include "parasite-syscall.h"

#include "protobuf.h"
#include "images/sa.pb-c.h"
#include "images/timer.pb-c.h"
#include "images/vma.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "asm/restore.h"
#include "asm/atomic.h"
#include "asm/bitops.h"

#include "cr-errno.h"

#include "pie/pie-relocs.h"

#ifndef arch_export_restore_thread
#define arch_export_restore_thread	__export_restore_thread
#endif

#ifndef arch_export_restore_task
#define arch_export_restore_task	__export_restore_task
#endif

#ifndef arch_export_unmap
#define arch_export_unmap		__export_unmap
#endif

static struct pstree_item *current;

static int restore_task_with_children(void *);
static int sigreturn_restore(pid_t pid, CoreEntry *core);
static int prepare_restorer_blob(void);
static int prepare_rlimits(int pid, CoreEntry *core);
static int prepare_posix_timers(int pid, CoreEntry *core);
static int prepare_signals(int pid, CoreEntry *core);

static int root_as_sibling;
static unsigned long helpers_pos = 0;
static int n_helpers = 0;
static unsigned long zombies_pos = 0;
static int n_zombies = 0;

static int crtools_prepare_shared(void)
{
	if (prepare_shared_fdinfo())
		return -1;

	/* We might want to remove ghost files on failed restore */
	if (collect_remaps_and_regfiles())
		return -1;

	/* dead pid remap needs to allocate task helpers which all tasks need
	 * to see */
	if (prepare_procfs_remaps())
		return -1;

	/* Connections are unlocked from criu */
	if (collect_inet_sockets())
		return -1;

	if (tty_prep_fds())
		return -1;

	if (prepare_cgroup())
		return -1;

	return 0;
}

/*
 * Collect order information:
 * - reg_file should be before remap, as the latter needs
 *   to find file_desc objects
 * - per-pid collects (mm and fd) should be after remap and
 *   reg_file since both per-pid ones need to get fdesc-s
 *   and bump counters on remaps if they exist
 */

static struct collect_image_info *cinfos[] = {
	&nsfile_cinfo,
	&pipe_cinfo,
	&fifo_cinfo,
	&unix_sk_cinfo,
	&packet_sk_cinfo,
	&netlink_sk_cinfo,
	&eventfd_cinfo,
	&epoll_tfd_cinfo,
	&epoll_cinfo,
	&signalfd_cinfo,
	&inotify_cinfo,
	&inotify_mark_cinfo,
	&fanotify_cinfo,
	&fanotify_mark_cinfo,
	&tty_info_cinfo,
	&tty_cinfo,
	&tunfile_cinfo,
	&ext_file_cinfo,
	&timerfd_cinfo,
	&file_locks_cinfo,
};

static int root_prepare_shared(void)
{
	int ret = 0, i;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	if (prepare_shared_tty())
		return -1;

	if (prepare_shared_reg_files())
		return -1;

	if (prepare_remaps())
		return -1;

	if (prepare_seccomp_filters())
		return -1;

	for (i = 0; i < ARRAY_SIZE(cinfos); i++) {
		ret = collect_image(cinfos[i]);
		if (ret)
			return -1;
	}

	if (collect_pipes())
		return -1;
	if (collect_fifo())
		return -1;
	if (collect_unix_sockets())
		return -1;

	if (tty_verify_active_pairs())
		return -1;

	for_each_pstree_item(pi) {
		if (pi->state == TASK_HELPER)
			continue;

		ret = prepare_mm_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi);
		if (ret < 0)
			break;

		ret = prepare_fs_pid(pi);
		if (ret < 0)
			break;
	}

	if (ret < 0)
		goto err;

	mark_pipe_master();

	ret = tty_setup_slavery();
	if (ret)
		goto err;

	ret = resolve_unix_peers();
	if (ret)
		goto err;

	ret = prepare_restorer_blob();
	if (ret)
		goto err;

	show_saved_shmems();
	show_saved_files();
err:
	return ret;
}

/* Map a private vma, if it is not mapped by a parent yet */
static int map_private_vma(struct vma_area *vma, void **tgt_addr,
			struct vma_area **pvma, struct list_head *pvma_list)
{
	int ret;
	void *addr, *paddr = NULL;
	unsigned long nr_pages, size;
	struct vma_area *p = *pvma;

	if (vma_area_is(vma, VMA_FILE_PRIVATE)) {
		ret = get_filemap_fd(vma);
		if (ret < 0) {
			pr_err("Can't fixup VMA's fd\n");
			return -1;
		}
		vma->e->fd = ret;
	}

	nr_pages = vma_entry_len(vma->e) / PAGE_SIZE;
	vma->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
	if (vma->page_bitmap == NULL)
		return -1;

	list_for_each_entry_from(p, pvma_list, list) {
		if (p->e->start > vma->e->start)
			 break;

		if (!vma_area_is_private(p, kdat.task_size))
			continue;

		 if (p->e->end != vma->e->end ||
		     p->e->start != vma->e->start)
			continue;

		/* Check flags, which must be identical for both vma-s */
		if ((vma->e->flags ^ p->e->flags) & (MAP_GROWSDOWN | MAP_ANONYMOUS))
			break;

		if (!(vma->e->flags & MAP_ANONYMOUS) &&
		    vma->e->shmid != p->e->shmid)
			break;

		pr_info("COW 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" vma\n",
			vma->e->start, vma->e->end, vma->e->pgoff);
		paddr = decode_pointer(p->premmaped_addr);

		break;
	}

	/*
	 * A grow-down VMA has a guard page, which protect a VMA below it.
	 * So one more page is mapped here to restore content of the first page
	 */
	if (vma->e->flags & MAP_GROWSDOWN) {
		vma->e->start -= PAGE_SIZE;
		if (paddr)
			paddr -= PAGE_SIZE;
	}

	size = vma_entry_len(vma->e);
	if (paddr == NULL) {
		/*
		 * The respective memory area was NOT found in the parent.
		 * Map a new one.
		 */
		pr_info("Map 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" vma\n",
			vma->e->start, vma->e->end, vma->e->pgoff);

		addr = mmap(*tgt_addr, size,
				vma->e->prot | PROT_WRITE,
				vma->e->flags | MAP_FIXED,
				vma->e->fd, vma->e->pgoff);

		if (addr == MAP_FAILED) {
			pr_perror("Unable to map ANON_VMA");
			return -1;
		}

		*pvma = p;
	} else {
		/*
		 * This region was found in parent -- remap it to inherit physical
		 * pages (if any) from it (and COW them later if required).
		 */
		vma->ppage_bitmap = p->page_bitmap;

		addr = mremap(paddr, size, size,
				MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
		if (addr != *tgt_addr) {
			pr_perror("Unable to remap a private vma");
			return -1;
		}

		*pvma = list_entry(p->list.next, struct vma_area, list);
	}

	vma->premmaped_addr = (unsigned long) addr;
	pr_debug("\tpremap 0x%016"PRIx64"-0x%016"PRIx64" -> %016lx\n",
		vma->e->start, vma->e->end, (unsigned long)addr);

	if (vma->e->flags & MAP_GROWSDOWN) { /* Skip gurad page */
		vma->e->start += PAGE_SIZE;
		vma->premmaped_addr += PAGE_SIZE;
	}

	if (vma_area_is(vma, VMA_FILE_PRIVATE))
		close(vma->e->fd);

	*tgt_addr += size;
	return 0;
}

static int premap_priv_vmas(struct vm_area_list *vmas, void *at)
{
	struct list_head *parent_vmas;
	struct vma_area *pvma, *vma;
	unsigned long pstart = 0;
	int ret = 0;
	LIST_HEAD(empty);

	/*
	 * Keep parent vmas at hands to check whether we can "inherit" them.
	 * See comments in map_private_vma.
	 */
	if (current->parent)
		parent_vmas = &rsti(current->parent)->vmas.h;
	else
		parent_vmas = &empty;

	pvma = list_first_entry(parent_vmas, struct vma_area, list);

	list_for_each_entry(vma, &vmas->h, list) {
		if (pstart > vma->e->start) {
			ret = -1;
			pr_err("VMA-s are not sorted in the image file\n");
			break;
		}
		pstart = vma->e->start;

		if (!vma_area_is_private(vma, kdat.task_size))
			continue;

		ret = map_private_vma(vma, &at, &pvma, parent_vmas);
		if (ret < 0)
			break;
	}

	return ret;
}

static int restore_priv_vma_content(void)
{
	struct vma_area *vma;
	int ret = 0;
	struct list_head *vmas = &rsti(current)->vmas.h;

	unsigned int nr_restored = 0;
	unsigned int nr_shared = 0;
	unsigned int nr_droped = 0;
	unsigned int nr_compared = 0;
	unsigned long va;
	struct page_read pr;

	vma = list_first_entry(vmas, struct vma_area, list);

	ret = open_page_read(current->pid.virt, &pr, PR_TASK);
	if (ret <= 0)
		return -1;

	/*
	 * Read page contents.
	 */
	while (1) {
		unsigned long off, i, nr_pages;
		struct iovec iov;

		ret = pr.get_pagemap(&pr, &iov);
		if (ret <= 0)
			break;

		va = (unsigned long)iov.iov_base;
		nr_pages = iov.iov_len / PAGE_SIZE;

		for (i = 0; i < nr_pages; i++) {
			unsigned char buf[PAGE_SIZE];
			void *p;

			/*
			 * The lookup is over *all* possible VMAs
			 * read from image file.
			 */
			while (va >= vma->e->end) {
				if (vma->list.next == vmas)
					goto err_addr;
				vma = list_entry(vma->list.next, struct vma_area, list);
			}

			/*
			 * Make sure the page address is inside existing VMA
			 * and the VMA it refers to still private one, since
			 * there is no guarantee that the data from pagemap is
			 * valid.
			 */
			if (va < vma->e->start)
				goto err_addr;
			else if (unlikely(!vma_area_is_private(vma, kdat.task_size))) {
				pr_err("Trying to restore page for non-private VMA\n");
				goto err_addr;
			}

			off = (va - vma->e->start) / PAGE_SIZE;
			p = decode_pointer((off) * PAGE_SIZE +
					vma->premmaped_addr);

			set_bit(off, vma->page_bitmap);
			if (vma->ppage_bitmap) { /* inherited vma */
				clear_bit(off, vma->ppage_bitmap);

				ret = pr.read_pages(&pr, va, 1, buf);
				if (ret < 0)
					goto err_read;

				va += PAGE_SIZE;
				nr_compared++;

				if (memcmp(p, buf, PAGE_SIZE) == 0) {
					nr_shared++; /* the page is cowed */
					continue;
				}

				nr_restored++;
				memcpy(p, buf, PAGE_SIZE);
			} else {
				int nr;

				/*
				 * Try to read as many pages as possible at once.
				 *
				 * Within the current pagemap we still have
				 * nr_pages - i pages (not all, as we might have
				 * switched VMA above), within the current VMA
				 * we have at most (vma->end - current_addr) bytes.
				 */

				nr = min_t(int, nr_pages - i, (vma->e->end - va) / PAGE_SIZE);

				ret = pr.read_pages(&pr, va, nr, p);
				if (ret < 0)
					goto err_read;

				va += nr * PAGE_SIZE;
				nr_restored += nr;
				i += nr - 1;

				bitmap_set(vma->page_bitmap, off + 1, nr - 1);
			}

		}

		if (pr.put_pagemap)
			pr.put_pagemap(&pr);
	}

err_read:
	pr.close(&pr);
	if (ret < 0)
		return ret;

	/* Remove pages, which were not shared with a child */
	list_for_each_entry(vma, vmas, list) {
		unsigned long size, i = 0;
		void *addr = decode_pointer(vma->premmaped_addr);

		if (vma->ppage_bitmap == NULL)
			continue;

		size = vma_entry_len(vma->e) / PAGE_SIZE;
		while (1) {
			/* Find all pages, which are not shared with this child */
			i = find_next_bit(vma->ppage_bitmap, size, i);

			if ( i >= size)
				break;

			ret = madvise(addr + PAGE_SIZE * i,
						PAGE_SIZE, MADV_DONTNEED);
			if (ret < 0) {
				pr_perror("madvise failed");
				return -1;
			}
			i++;
			nr_droped++;
		}
	}

	cnt_add(CNT_PAGES_COMPARED, nr_compared);
	cnt_add(CNT_PAGES_SKIPPED_COW, nr_shared);
	cnt_add(CNT_PAGES_RESTORED, nr_restored);

	pr_info("nr_restored_pages: %d\n", nr_restored);
	pr_info("nr_shared_pages:   %d\n", nr_shared);
	pr_info("nr_droped_pages:   %d\n", nr_droped);

	return 0;

err_addr:
	pr_err("Page entry address %lx outside of VMA %lx-%lx\n",
	       va, (long)vma->e->start, (long)vma->e->end);
	return -1;
}

static int prepare_mappings(void)
{
	int ret = 0;
	void *addr;
	struct vm_area_list *vmas;

	void *old_premmapped_addr = NULL;
	unsigned long old_premmapped_len;

	vmas = &rsti(current)->vmas;
	if (vmas->nr == 0) /* Zombie */
		goto out;

	/* Reserve a place for mapping private vma-s one by one */
	addr = mmap(NULL, vmas->priv_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		ret = -1;
		pr_perror("Unable to reserve memory (%lu bytes)", vmas->priv_size);
		goto out;
	}

	old_premmapped_addr = rsti(current)->premmapped_addr;
	old_premmapped_len = rsti(current)->premmapped_len;
	rsti(current)->premmapped_addr = addr;
	rsti(current)->premmapped_len = vmas->priv_size;

	ret = premap_priv_vmas(vmas, addr);
	if (ret < 0)
		goto out;

	ret = restore_priv_vma_content();
	if (ret < 0)
		goto out;

	if (old_premmapped_addr) {
		ret = munmap(old_premmapped_addr, old_premmapped_len);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)",
					old_premmapped_addr, old_premmapped_len);
	}

out:
	return ret;
}

/*
 * A gard page must be unmapped after restoring content and
 * forking children to restore COW memory.
 */
static int unmap_guard_pages()
{
	struct vma_area *vma;
	struct list_head *vmas = &rsti(current)->vmas.h;

	list_for_each_entry(vma, vmas, list) {
		if (!vma_area_is_private(vma, kdat.task_size))
			continue;

		if (vma->e->flags & MAP_GROWSDOWN) {
			void *addr = decode_pointer(vma->premmaped_addr);

			if (munmap(addr - PAGE_SIZE, PAGE_SIZE)) {
				pr_perror("Can't unmap guard page");
				return -1;
			}
		}
	}

	return 0;
}

static int open_vmas(int pid)
{
	struct vma_area *vma;
	int ret = 0;
	struct list_head *vmas = &rsti(current)->vmas.h;

	list_for_each_entry(vma, vmas, list) {
		if (!(vma_area_is(vma, VMA_AREA_REGULAR)))
			continue;

		pr_info("Opening 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" (%x) vma\n",
				vma->e->start, vma->e->end,
				vma->e->pgoff, vma->e->status);

		if (vma_area_is(vma, VMA_AREA_SYSVIPC))
			ret = vma->e->shmid;
		else if (vma_area_is(vma, VMA_ANON_SHARED))
			ret = get_shmem_fd(pid, vma->e);
		else if (vma_area_is(vma, VMA_FILE_SHARED))
			ret = get_filemap_fd(vma);
		else if (vma_area_is(vma, VMA_AREA_SOCKET))
			ret = get_socket_fd(pid, vma->e);
		else
			continue;

		if (ret < 0) {
			pr_err("Can't fixup fd\n");
			break;
		}

		pr_info("\t`- setting %d as mapping fd\n", ret);
		vma->e->fd = ret;
	}

	return ret < 0 ? -1 : 0;
}

static rt_sigaction_t sigchld_act;
static rt_sigaction_t parent_act[SIGMAX];

static bool sa_inherited(int sig, rt_sigaction_t *sa)
{
	rt_sigaction_t *pa;

	if (current == root_item)
		return false; /* XXX -- inherit from CRIU? */

	pa = &parent_act[sig];
	return pa->rt_sa_handler == sa->rt_sa_handler &&
		pa->rt_sa_flags == sa->rt_sa_flags &&
		pa->rt_sa_restorer == sa->rt_sa_restorer &&
		pa->rt_sa_mask.sig[0] == sa->rt_sa_mask.sig[0];
}

static int prepare_sigactions(void)
{
	int pid = current->pid.virt;
	rt_sigaction_t act;
	struct cr_img *img;
	SaEntry *e;
	int sig, rst = 0;
	int ret = 0;

	if (!task_alive(current))
		return 0;

	pr_info("Restore sigacts for %d\n", pid);

	img = open_image(CR_FD_SIGACT, O_RSTR, pid);
	if (!img)
		return -1;

	for (sig = 1; sig <= SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = pb_read_one_eof(img, &e, PB_SIGACT);
		if (ret == 0) {
			if (sig != SIGMAX_OLD + 1) { /* backward compatibility */
				pr_err("Unexpected EOF %d\n", sig);
				ret = -1;
				break;
			}
			pr_warn("This format of sigacts-%d.img is deprecated\n", pid);
			break;
		}
		if (ret < 0)
			break;

		ASSIGN_TYPED(act.rt_sa_handler, decode_pointer(e->sigaction));
		ASSIGN_TYPED(act.rt_sa_flags, e->flags);
		ASSIGN_TYPED(act.rt_sa_restorer, decode_pointer(e->restorer));
		ASSIGN_TYPED(act.rt_sa_mask.sig[0], e->mask);

		sa_entry__free_unpacked(e, NULL);

		if (sig == SIGCHLD) {
			sigchld_act = act;
			continue;
		}

		if (sa_inherited(sig - 1, &act))
			continue;

		/*
		 * A pure syscall is used, because glibc
		 * sigaction overwrites se_restorer.
		 */
		ret = syscall(SYS_rt_sigaction, sig, &act, NULL, sizeof(k_rtsigset_t));
		if (ret < 0) {
			errno = -ret;
			pr_perror("Can't restore sigaction");
			goto err;
		}

		parent_act[sig - 1] = act;
		rst++;
	}

	pr_info("Restored %d/%d sigacts\n", rst,
			SIGMAX - 3 /* KILL, STOP and CHLD */);

err:
	close_image(img);
	return ret;
}

static int collect_child_pids(int state, int *n)
{
	struct pstree_item *pi;

	*n = 0;
	list_for_each_entry(pi, &current->children, sibling) {
		pid_t *child;

		if (pi->state != state)
			continue;

		child = rst_mem_alloc(sizeof(*child), RM_PRIVATE);
		if (!child)
			return -1;

		(*n)++;
		*child = pi->pid.virt;
	}

	return 0;
}

static int collect_helper_pids()
{
	helpers_pos = rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_HELPER, &n_helpers);
}

static int collect_zombie_pids()
{
	zombies_pos = rst_mem_align_cpos(RM_PRIVATE);
	return collect_child_pids(TASK_DEAD, &n_zombies);
}

static int open_cores(int pid, CoreEntry *leader_core)
{
	int i, tpid;
	CoreEntry **cores = NULL;

	cores = xmalloc(sizeof(*cores)*current->nr_threads);
	if (!cores)
		goto err;

	for (i = 0; i < current->nr_threads; i++) {
		tpid = current->threads[i].virt;

		if (tpid == pid)
			cores[i] = leader_core;
		else {
			struct cr_img *img;

			img = open_image(CR_FD_CORE, O_RSTR, tpid);
			if (!img) {
				pr_err("Can't open core data for thread %d\n", tpid);
				goto err;
			}

			if (pb_read_one(img, &cores[i], PB_CORE) <= 0) {
				close_image(img);
				goto err;
			}

			close_image(img);
		}
	}

	current->core = cores;

	return 0;
err:
	xfree(cores);
	return -1;
}

static int prepare_oom_score_adj(int value)
{
	int fd, ret = 0;
	char buf[11];

	fd = open_proc_rw(PROC_SELF, "oom_score_adj");
	if (fd < 0)
		return -1;

	snprintf(buf, 11, "%d", value);

	if (write(fd, buf, 11) < 0) {
		pr_perror("Write %s to /proc/self/oom_score_adj failed", buf);
		ret = -1;
	}

	close(fd);
	return ret;
}

static int prepare_proc_misc(pid_t pid, TaskCoreEntry *tc)
{
	int ret;

	/* loginuid value is critical to restore */
	if (kdat.has_loginuid && tc->has_loginuid &&
			tc->loginuid != INVALID_UID) {
		ret = prepare_loginuid(tc->loginuid, LOG_ERROR);
		if (ret < 0)
			return ret;
	}

	/* oom_score_adj is not critical: only log errors */
	if (tc->has_oom_score_adj && tc->oom_score_adj != 0)
		prepare_oom_score_adj(tc->oom_score_adj);

	return 0;
}

static int restore_one_alive_task(int pid, CoreEntry *core)
{
	pr_info("Restoring resources\n");

	rst_mem_switch_to_private();

	if (prepare_fds(current))
		return -1;

	if (prepare_file_locks(pid))
		return -1;

	if (open_vmas(pid))
		return -1;

	if (open_cores(pid, core))
		return -1;

	if (prepare_signals(pid, core))
		return -1;

	if (prepare_posix_timers(pid, core))
		return -1;

	if (prepare_rlimits(pid, core) < 0)
		return -1;

	if (collect_helper_pids() < 0)
		return -1;

	if (collect_zombie_pids() < 0)
		return -1;

	if (inherit_fd_fini() < 0)
		return -1;

	if (prepare_proc_misc(pid, core->tc))
		return -1;

	return sigreturn_restore(pid, core);
}

static void zombie_prepare_signals(void)
{
	sigset_t blockmask;
	int sig;
	struct sigaction act;

	sigfillset(&blockmask);
	sigprocmask(SIG_UNBLOCK, &blockmask, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_DFL;

	for (sig = 1; sig <= SIGMAX; sig++)
		sigaction(sig, &act, NULL);
}

#define SIG_FATAL_MASK	(	\
		(1 << SIGHUP)	|\
		(1 << SIGINT)	|\
		(1 << SIGQUIT)	|\
		(1 << SIGILL)	|\
		(1 << SIGTRAP)	|\
		(1 << SIGABRT)	|\
		(1 << SIGIOT)	|\
		(1 << SIGBUS)	|\
		(1 << SIGFPE)	|\
		(1 << SIGKILL)	|\
		(1 << SIGUSR1)	|\
		(1 << SIGSEGV)	|\
		(1 << SIGUSR2)	|\
		(1 << SIGPIPE)	|\
		(1 << SIGALRM)	|\
		(1 << SIGTERM)	|\
		(1 << SIGXCPU)	|\
		(1 << SIGXFSZ)	|\
		(1 << SIGVTALRM)|\
		(1 << SIGPROF)	|\
		(1 << SIGPOLL)	|\
		(1 << SIGIO)	|\
		(1 << SIGSYS)	|\
		(1 << SIGUNUSED)|\
		(1 << SIGSTKFLT)|\
		(1 << SIGPWR)	 \
	)

static inline int sig_fatal(int sig)
{
	return (sig > 0) && (sig < SIGMAX) && (SIG_FATAL_MASK & (1UL << sig));
}

struct task_entries *task_entries;
static unsigned long task_entries_pos;

static int restore_one_zombie(CoreEntry *core)
{
	int exit_code = core->tc->exit_code;

	pr_info("Restoring zombie with %d code\n", exit_code);

	if (inherit_fd_fini() < 0)
		return -1;

	prctl(PR_SET_NAME, (long)(void *)core->tc->comm, 0, 0, 0);

	if (task_entries != NULL) {
		restore_finish_stage(CR_STATE_RESTORE);
		zombie_prepare_signals();
	}

	if (exit_code & 0x7f) {
		int signr;

		/* prevent generating core files */
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
			pr_perror("Can't drop the dumpable flag");

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(current->pid.virt, signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int check_core(CoreEntry *core, struct pstree_item *me)
{
	int ret = -1;

	if (core->mtype != CORE_ENTRY__MARCH) {
		pr_err("Core march mismatch %d\n", (int)core->mtype);
		goto out;
	}

	if (!core->tc) {
		pr_err("Core task state data missed\n");
		goto out;
	}

	if (core->tc->task_state != TASK_DEAD) {
		if (!core->ids && !me->ids) {
			pr_err("Core IDS data missed for non-zombie\n");
			goto out;
		}

		if (!CORE_THREAD_ARCH_INFO(core)) {
			pr_err("Core info data missed for non-zombie\n");
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

static int restore_one_task(int pid, CoreEntry *core)
{
	int ret;

	/* No more fork()-s => no more per-pid logs */

	if (task_alive(current))
		ret = restore_one_alive_task(pid, core);
	else if (current->state == TASK_DEAD)
		ret = restore_one_zombie(core);
	else if (current->state == TASK_HELPER) {
		restore_finish_stage(CR_STATE_RESTORE);
		ret = 0;
	} else {
		pr_err("Unknown state in code %d\n", (int)core->tc->task_state);
		ret = -1;
	}

	if (core)
		core_entry__free_unpacked(core, NULL);
	return ret;
}

/* All arguments should be above stack, because it grows down */
struct cr_clone_arg {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[128] __stack_aligned__;
	char stack_ptr[0];
	struct pstree_item *item;
	unsigned long clone_flags;
	int fd;

	CoreEntry *core;
};

static void maybe_clone_parent(struct pstree_item *item,
			      struct cr_clone_arg *ca)
{
	/*
	 * zdtm runs in kernel 3.11, which has the problem described below. We
	 * avoid this by including the pdeath_sig test. Once users/zdtm migrate
	 * off of 3.11, this condition can be simplified to just test the
	 * options and not have the pdeath_sig test.
	 */
	if (opts.restore_sibling) {
		/*
		 * This means we're called from lib's criu_restore_child().
		 * In that case create the root task as the child one to+
		 * the caller. This is the only way to correctly restore the
		 * pdeath_sig of the root task. But also looks nice.
		 *
		 * Alternatively, if we are --restore-detached, a similar trick is
		 * needed to correctly restore pdeath_sig and prevent processes from
		 * dying once restored.
		 *
		 * There were a problem in kernel 3.11 -- CLONE_PARENT can't be
		 * set together with CLONE_NEWPID, which has been solved in further
		 * versions of the kernels, but we treat 3.11 as a base, so at
		 * least warn a user about potential problems.
		 */
		rsti(item)->clone_flags |= CLONE_PARENT;
		root_as_sibling = 1;
		if (rsti(item)->clone_flags & CLONE_NEWPID)
			pr_warn("Set CLONE_PARENT | CLONE_NEWPID but it might cause restore problem,"
				"because not all kernels support such clone flags combinations!\n");
	} else if (opts.restore_detach) {
		if (ca->core->thread_core->pdeath_sig)
			pr_warn("Root task has pdeath_sig configured, so it will receive one _right_"
				"after restore on CRIU exit\n");
	}
}

static inline int fork_with_pid(struct pstree_item *item)
{
	struct cr_clone_arg ca;
	int ret = -1;
	pid_t pid = item->pid.virt;

	if (item->state != TASK_HELPER) {
		struct cr_img *img;

		img = open_image(CR_FD_CORE, O_RSTR, pid);
		if (!img)
			return -1;

		ret = pb_read_one(img, &ca.core, PB_CORE);
		close_image(img);

		if (ret < 0)
			return -1;

		if (check_core(ca.core, item))
			return -1;

		item->state = ca.core->tc->task_state;
		rsti(item)->cg_set = ca.core->tc->cg_set;

		rsti(item)->has_seccomp = ca.core->tc->seccomp_mode != SECCOMP_MODE_DISABLED;

		if (item->state == TASK_DEAD)
			rsti(item->parent)->nr_zombies++;
		else if (!task_alive(item)) {
			pr_err("Unknown task state %d\n", item->state);
			return -1;
		}

		if (unlikely(item == root_item))
			maybe_clone_parent(item, &ca);
	} else {
		/*
		 * Helper entry will not get moved around and thus
		 * will live in the parent's cgset.
		 */
		rsti(item)->cg_set = rsti(item->parent)->cg_set;
		ca.core = NULL;
	}

	ret = -1;

	ca.item = item;
	ca.clone_flags = rsti(item)->clone_flags;

	BUG_ON(ca.clone_flags & CLONE_VM);

	pr_info("Forking task with %d pid (flags 0x%lx)\n", pid, ca.clone_flags);

	if (!(ca.clone_flags & CLONE_NEWPID)) {
		char buf[32];
		int len;

		ca.fd = open_proc_rw(PROC_GEN, LAST_PID_PATH);
		if (ca.fd < 0) {
			pr_perror("%d: Can't open %s", pid, LAST_PID_PATH);
			goto err;
		}

		if (flock(ca.fd, LOCK_EX)) {
			close(ca.fd);
			pr_perror("%d: Can't lock %s", pid, LAST_PID_PATH);
			goto err;
		}

		len = snprintf(buf, sizeof(buf), "%d", pid - 1);
		if (write(ca.fd, buf, len) != len) {
			pr_perror("%d: Write %s to %s", pid, buf, LAST_PID_PATH);
			goto err_unlock;
		}
	} else {
		ca.fd = -1;
		BUG_ON(pid != INIT_PID);
	}

	/*
	 * Some kernel modules, such as netwrok packet generator
	 * run kernel thread upon net-namespace creattion taking
	 * the @pid we've been requeting via LAST_PID_PATH interface
	 * so that we can't restore a take with pid needed.
	 *
	 * Here is an idea -- unhare net namespace in callee instead.
	 */
	/*
	 * The cgroup namespace is also unshared explicitly in the
	 * move_in_cgroup(), so drop this flag here as well.
	 */
	ret = clone(restore_task_with_children, ca.stack_ptr,
		    (ca.clone_flags & (~CLONE_NEWNET | ~CLONE_NEWCGROUP)) | SIGCHLD, &ca);

	if (ret < 0) {
		pr_perror("Can't fork for %d", pid);
		goto err_unlock;
	}


	if (item == root_item) {
		item->pid.real = ret;
		pr_debug("PID: real %d virt %d\n",
				item->pid.real, item->pid.virt);
	}

	if (opts.pidfile && root_item == item) {
		int pid;

		pid = ret;

		ret = write_pidfile(pid);
		if (ret < 0) {
			pr_perror("Can't write pidfile");
			kill(pid, SIGKILL);
		}
	}

err_unlock:
	if (ca.fd >= 0) {
		if (flock(ca.fd, LOCK_UN))
			pr_perror("%d: Can't unlock %s", pid, LAST_PID_PATH);

		close(ca.fd);
	}
err:
	if (ca.core)
		core_entry__free_unpacked(ca.core, NULL);
	return ret;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	struct pstree_item *pi;
	pid_t pid = siginfo->si_pid;
	int status;
	int exit;

	exit = (siginfo->si_code == CLD_EXITED);
	status = siginfo->si_status;

	/* skip scripts */
	if (!current && root_item->pid.real != pid) {
		pid = waitpid(root_item->pid.real, &status, WNOHANG);
		if (pid <= 0)
			return;
		exit = WIFEXITED(status);
		status = exit ? WEXITSTATUS(status) : WTERMSIG(status);
	}

	if (!current && siginfo->si_code == CLD_TRAPPED &&
				siginfo->si_status == SIGCHLD) {
		/* The root task is ptraced. Allow it to handle SIGCHLD */
		ptrace(PTRACE_CONT, siginfo->si_pid, 0, SIGCHLD);
		return;
	}

	if (!current || status)
		goto err;

	while (pid) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			return;

		exit = WIFEXITED(status);
		status = exit ? WEXITSTATUS(status) : WTERMSIG(status);
		if (status)
			break;

		/* Exited (with zero code) helpers are OK */
		list_for_each_entry(pi, &current->children, sibling)
			if (pi->pid.virt == siginfo->si_pid)
				break;

		BUG_ON(&pi->sibling == &current->children);
		if (pi->state != TASK_HELPER)
			break;
	}

err:
	if (exit)
		pr_err("%d exited, status=%d\n", pid, status);
	else
		pr_err("%d killed by signal %d\n", pid, status);

	futex_abort_and_wake(&task_entries->nr_in_progress);
}

static int criu_signals_setup(void)
{
	int ret;
	struct sigaction act;
	sigset_t blockmask;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, NULL);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	/*
	 * The block mask will be restored in sigreturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);

	/*
	 * Here we use SIG_SETMASK instead of SIG_BLOCK to avoid the case where
	 * we've been forked from a parent who had blocked SIGCHLD. If SIGCHLD
	 * is blocked when a task dies (e.g. if the task fails to restore
	 * somehow), we hang because our SIGCHLD handler is never run. Since we
	 * depend on SIGCHLD being unblocked, let's set the mask explicitly.
	 */
	ret = sigprocmask(SIG_SETMASK, &blockmask, NULL);
	if (ret < 0) {
		pr_perror("Can't block signals");
		return -1;
	}

	return 0;
}

static void restore_sid(void)
{
	pid_t sid;

	/*
	 * SID can only be reset to pid or inherited from parent.
	 * Thus we restore it right here to let our kids inherit
	 * one in case they need it.
	 *
	 * PGIDs are restored late when all tasks are forked and
	 * we can call setpgid() on custom values.
	 */

	if (current->pid.virt == current->sid) {
		pr_info("Restoring %d to %d sid\n", current->pid.virt, current->sid);
		sid = setsid();
		if (sid != current->sid) {
			pr_perror("Can't restore sid (%d)", sid);
			exit(1);
		}
	} else {
		sid = getsid(getpid());
		if (sid != current->sid) {
			/* Skip the root task if it's not init */
			if (current == root_item && root_item->pid.virt != INIT_PID)
				return;
			pr_err("Requested sid %d doesn't match inherited %d\n",
					current->sid, sid);
			exit(1);
		}
	}
}

static void restore_pgid(void)
{
	/*
	 * Unlike sessions, process groups (a.k.a. pgids) can be joined
	 * by any task, provided the task with pid == pgid (group leader)
	 * exists. Thus, in order to restore pgid we must make sure that
	 * group leader was born and created the group, then join one.
	 *
	 * We do this _before_ finishing the forking stage to make sure
	 * helpers are still with us.
	 */

	pid_t pgid, my_pgid = current->pgid;

	pr_info("Restoring %d to %d pgid\n", current->pid.virt, my_pgid);

	pgid = getpgrp();
	if (my_pgid == pgid)
		return;

	if (my_pgid != current->pid.virt) {
		struct pstree_item *leader;

		/*
		 * Wait for leader to become such.
		 * Missing leader means we're going to crtools
		 * group (-j option).
		 */

		leader = rsti(current)->pgrp_leader;
		if (leader) {
			BUG_ON(my_pgid != leader->pid.virt);
			futex_wait_until(&rsti(leader)->pgrp_set, 1);
		}
	}

	pr_info("\twill call setpgid, mine pgid is %d\n", pgid);
	if (setpgid(0, my_pgid) != 0) {
		pr_perror("Can't restore pgid (%d/%d->%d)", current->pid.virt, pgid, current->pgid);
		exit(1);
	}

	if (my_pgid == current->pid.virt)
		futex_set_and_wake(&rsti(current)->pgrp_set, 1);
}

static int mount_proc(void)
{
	int fd, ret;
	char proc_mountpoint[] = "crtools-proc.XXXXXX";

	if (mkdtemp(proc_mountpoint) == NULL) {
		pr_perror("mkdtemp failed %s", proc_mountpoint);
		return -1;
	}

	pr_info("Mount procfs in %s\n", proc_mountpoint);
	if (mount("proc", proc_mountpoint, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
		pr_perror("mount failed");
		rmdir(proc_mountpoint);
		return -1;
	}

	ret = fd = open_detach_mount(proc_mountpoint);
	if (fd >= 0) {
		ret = set_proc_fd(fd);
		close(fd);
	}

	return ret;
}

/*
 * Tasks cannot change sid (session id) arbitrary, but can either
 * inherit one from ancestor, or create a new one with id equal to
 * their pid. Thus sid-s restore is tied with children creation.
 */

static int create_children_and_session(void)
{
	int ret;
	struct pstree_item *child;

	pr_info("Restoring children in alien sessions:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (!restore_before_setsid(child))
			continue;

		BUG_ON(child->born_sid != -1 && getsid(getpid()) != child->born_sid);

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	if (current->parent)
		restore_sid();

	pr_info("Restoring children in our session:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (restore_before_setsid(child))
			continue;

		ret = fork_with_pid(child);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	pid_t pid;
	int ret;

	current = ca->item;

	if (current != root_item) {
		char buf[12];
		int fd;

		/* Determine PID in CRIU's namespace */
		fd = get_service_fd(CR_PROC_FD_OFF);
		if (fd < 0)
			goto err;

		ret = readlinkat(fd, "self", buf, sizeof(buf) - 1);
		if (ret < 0) {
			pr_perror("Unable to read the /proc/self link");
			goto err;
		}
		buf[ret] = '\0';

		current->pid.real = atoi(buf);
		pr_debug("PID: real %d virt %d\n",
				current->pid.real, current->pid.virt);
	}

	if ( !(ca->clone_flags & CLONE_FILES))
		close_safe(&ca->fd);

	if (current->state != TASK_HELPER) {
		ret = clone_service_fd(rsti(current)->service_fd_id);
		if (ret)
			goto err;
	}

	pid = getpid();
	if (current->pid.virt != pid) {
		pr_err("Pid %d do not match expected %d\n", pid, current->pid.virt);
		set_task_cr_err(EEXIST);
		goto err;
	}

	ret = log_init_by_pid();
	if (ret < 0)
		goto err;

	if (ca->clone_flags & CLONE_NEWNET) {
		ret = unshare(CLONE_NEWNET);
		if (ret) {
			pr_perror("Can't unshare net-namespace");
			goto err;
		}
	}

	if (!(ca->clone_flags & CLONE_FILES)) {
		ret = close_old_fds();
		if (ret)
			goto err;
	}

	/* Restore root task */
	if (current->parent == NULL) {
		if (restore_finish_stage(CR_STATE_RESTORE_NS) < 0)
			goto err;

		pr_info("Calling restore_sid() for init\n");
		restore_sid();

		/*
		 * We need non /proc proc mount for restoring pid and mount
		 * namespaces and do not care for the rest of the cases.
		 * Thus -- mount proc at custom location for any new namespace
		 */
		if (mount_proc())
			goto err;

		if (prepare_namespace(current, ca->clone_flags))
			goto err;

		if (root_prepare_shared())
			goto err;

		if (restore_finish_stage(CR_STATE_RESTORE_SHARED) < 0)
			goto err;
	}

	if (restore_task_mnt_ns(current))
		goto err;

	if (prepare_mappings())
		goto err;

	/*
	 * Call this _before_ forking to optimize cgroups
	 * restore -- if all tasks live in one set of cgroups
	 * we will only move the root one there, others will
	 * just have it inherited.
	 */
	if (prepare_task_cgroup(current) < 0)
		goto err;

	if (prepare_sigactions() < 0)
		goto err;

	if (fault_injected(FI_RESTORE_ROOT_ONLY)) {
		pr_info("fault: Restore root task failure!\n");
		BUG();
	}

	if (create_children_and_session())
		goto err;


	if (unmap_guard_pages())
		goto err;

	restore_pgid();

	if (restore_finish_stage(CR_STATE_FORKING) < 0)
		goto err;

	if (current->parent == NULL) {
		if (depopulate_roots_yard())
			goto err;

		fini_restore_mntns();
	}

	if (restore_one_task(current->pid.virt, ca->core))
		goto err;

	return 0;

err:
	if (current->parent == NULL)
		futex_abort_and_wake(&task_entries->nr_in_progress);
	exit(1);
}

static inline int stage_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_FAIL:
		return 0;
	case CR_STATE_RESTORE_NS:
	case CR_STATE_RESTORE_SHARED:
		return 1;
	case CR_STATE_FORKING:
		return task_entries->nr_tasks + task_entries->nr_helpers;
	case CR_STATE_RESTORE:
		return task_entries->nr_threads + task_entries->nr_helpers;
	case CR_STATE_RESTORE_SIGCHLD:
		return task_entries->nr_threads;
	case CR_STATE_RESTORE_CREDS:
		return task_entries->nr_threads;
	}

	BUG();
	return -1;
}

static int restore_wait_inprogress_tasks()
{
	int ret;
	futex_t *np = &task_entries->nr_in_progress;

	futex_wait_while_gt(np, 0);
	ret = (int)futex_get(np);
	if (ret < 0) {
		set_cr_errno(get_task_cr_err());
		return ret;
	}

	return 0;
}

static void __restore_switch_stage(int next_stage)
{
	futex_set(&task_entries->nr_in_progress,
			stage_participants(next_stage));
	futex_set_and_wake(&task_entries->start, next_stage);
}

static int restore_switch_stage(int next_stage)
{
	__restore_switch_stage(next_stage);
	return restore_wait_inprogress_tasks();
}

static int attach_to_tasks(bool root_seized)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid = item->pid.real;
		int status, i;

		if (!task_alive(item))
			continue;

		if (parse_threads(item->pid.real, &item->threads, &item->nr_threads))
			return -1;

		for (i = 0; i < item->nr_threads; i++) {
			pid = item->threads[i].real;

			if (item != root_item || !root_seized || i != 0) {
				if (ptrace(PTRACE_SEIZE, pid, 0, 0)) {
					pr_perror("Can't attach to %d", pid);
					return -1;
				}
			}
			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}


			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			/*
			 * Suspend seccomp if necessary. We need to do this because
			 * although seccomp is restored at the very end of the
			 * restorer blob (and the final sigreturn is ok), here we're
			 * doing an munmap in the process, which may be blocked by
			 * seccomp and cause the task to be killed.
			 */
			if (rsti(item)->has_seccomp && suspend_seccomp(pid) < 0)
				pr_err("failed to suspend seccomp, restore will probably fail...\n");

			if (ptrace(PTRACE_CONT, pid, NULL, NULL) ) {
				pr_perror("Unable to resume %d", pid);
				return -1;
			}
		}
	}

	return 0;
}

static int catch_tasks(bool root_seized, enum trace_flags *flag)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid = item->pid.real;
		int status, i, ret;

		if (!task_alive(item))
			continue;

		if (parse_threads(item->pid.real, &item->threads, &item->nr_threads))
			return -1;

		for (i = 0; i < item->nr_threads; i++) {
			pid = item->threads[i].real;

			if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
				pr_perror("Can't interrupt the %d task", pid);
				return -1;
			}

			if (wait4(pid, &status, __WALL, NULL) != pid) {
				pr_perror("waitpid(%d) failed", pid);
				return -1;
			}

			ret = ptrace_stop_pie(pid, rsti(item)->breakpoint, flag);
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}

static int clear_breakpoints()
{
	struct pstree_item *item;
	int ret = 0, i;

	for_each_pstree_item(item) {
		if (!task_alive(item))
			continue;
		for (i = 0; i < item->nr_threads; i++)
			ret |= ptrace_flush_breakpoints(item->threads[i].real);
	}

	return ret;
}

static void finalize_restore(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid = item->pid.real;
		struct parasite_ctl *ctl;

		if (!task_alive(item))
			continue;

		/* Unmap the restorer blob */
		ctl = parasite_prep_ctl(pid, NULL);
		if (ctl == NULL)
			continue;

		parasite_unmap(ctl, (unsigned long)rsti(item)->munmap_restorer);

		xfree(ctl);

		if (item->state == TASK_STOPPED)
			kill(item->pid.real, SIGSTOP);
	}
}

static void finalize_restore_detach(int status)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		pid_t pid;
		int i;

		if (!task_alive(item))
			continue;

		for (i = 0; i < item->nr_threads; i++) {
			pid = item->threads[i].real;
			if (pid < 0) {
				BUG_ON(status >= 0);
				break;
			}

			if (ptrace(PTRACE_DETACH, pid, NULL, 0))
				pr_perror("Unable to execute %d", pid);
		}
	}
}

static void ignore_kids(void)
{
	struct sigaction sa = { .sa_handler = SIG_DFL };

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		pr_perror("Restoring CHLD sigaction failed");
}

static unsigned int saved_loginuid;

static int prepare_userns_hook(void)
{
	int ret;

	if (!kdat.has_loginuid)
		return 0;
	/*
	 * Save old loginuid and set it to INVALID_UID:
	 * this value means that loginuid is unset and it will be inherited.
	 * After you set some value to /proc/<>/loginuid it can't be changed
	 * inside container due to permissions.
	 * But you still can set this value if it was unset.
	 */
	saved_loginuid = parse_pid_loginuid(getpid(), &ret, false);
	if (ret < 0)
		return -1;

	if (prepare_loginuid(INVALID_UID, LOG_ERROR) < 0) {
		pr_err("Setting loginuid for CT init task failed, CAP_AUDIT_CONTROL?");
		return -1;
	}
	return 0;
}

static void restore_origin_ns_hook(void)
{
	if (!kdat.has_loginuid)
		return;

	/* not critical: it does not affect CT in any way */
	if (prepare_loginuid(saved_loginuid, LOG_ERROR) < 0)
		pr_err("Restore original /proc/self/loginuid failed");
}

static int restore_root_task(struct pstree_item *init)
{
	enum trace_flags flag = TRACE_ALL;
	int ret, fd, mnt_ns_fd = -1;
	int clean_remaps = 1;

	ret = run_scripts(ACT_PRE_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to pre-restore script ret code %d\n", ret);
		return -1;
	}

	fd = open("/proc", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc");
		return -1;
	}

	ret = install_service_fd(CR_PROC_FD_OFF, fd);
	close(fd);
	if (ret < 0)
		return -1;

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	if (init->pid.virt == INIT_PID) {
		if (!(root_ns_mask & CLONE_NEWPID)) {
			pr_err("This process tree can only be restored "
				"in a new pid namespace.\n"
				"criu should be re-executed with the "
				"\"--namespace pid\" option.\n");
			return -1;
		}
	} else	if (root_ns_mask & CLONE_NEWPID) {
		pr_err("Can't restore pid namespace without the process init\n");
		return -1;
	}

	if (prepare_userns_hook())
		return -1;

	if (prepare_namespace_before_tasks())
		return -1;

	futex_set(&task_entries->nr_in_progress,
			stage_participants(CR_STATE_RESTORE_NS));

	ret = fork_with_pid(init);
	if (ret < 0)
		goto out;

	restore_origin_ns_hook();

	if (root_as_sibling) {
		struct sigaction act;
		/*
		 * Root task will be our sibling. This means, that
		 * we will not notice when (if) it dies in SIGCHLD
		 * handler, but we should. To do this -- attach to
		 * the guy with ptrace (below) and (!) make the kernel
		 * deliver us the signal when it will get stopped.
		 * It will in case of e.g. segfault before handling
		 * the signal.
		 */
		sigaction(SIGCHLD, NULL, &act);
		act.sa_flags &= ~SA_NOCLDSTOP;
		sigaction(SIGCHLD, &act, NULL);

		if (ptrace(PTRACE_SEIZE, init->pid.real, 0, 0)) {
			pr_perror("Can't attach to init");
			goto out_kill;
		}
	}

	/*
	 * uid_map and gid_map must be filled from a parent user namespace.
	 * prepare_userns_creds() must be called after filling mappings.
	 */
	if ((root_ns_mask & CLONE_NEWUSER) && prepare_userns(init))
		goto out_kill;

	pr_info("Wait until namespaces are created\n");
	ret = restore_wait_inprogress_tasks();
	if (ret)
		goto out_kill;

	if (root_ns_mask & CLONE_NEWNS) {
		mnt_ns_fd = open_proc(init->pid.real, "ns/mnt");
		if (mnt_ns_fd < 0) {
			pr_perror("Can't open init's mntns fd");
			goto out_kill;
		}
	}

	ret = run_scripts(ACT_SETUP_NS);
	if (ret)
		goto out_kill;

	timing_start(TIME_FORK);
	ret = restore_switch_stage(CR_STATE_RESTORE_SHARED);
	if (ret < 0)
		goto out_kill;

	ret = run_scripts(ACT_POST_SETUP_NS);
	if (ret)
		goto out_kill;

	ret = restore_switch_stage(CR_STATE_FORKING);
	if (ret < 0)
		goto out_kill;

	timing_stop(TIME_FORK);

	ret = restore_switch_stage(CR_STATE_RESTORE);
	if (ret < 0)
		goto out_kill;

	ret = restore_switch_stage(CR_STATE_RESTORE_SIGCHLD);
	if (ret < 0)
		goto out_kill;

	/*
	 * The task_entries->nr_zombies is updated in the
	 * CR_STATE_RESTORE_SIGCHLD in pie code.
	 */
	task_entries->nr_threads -= atomic_read(&task_entries->nr_zombies);

	/*
	 * There is no need to call try_clean_remaps() after this point,
	 * as restore went OK and all ghosts were removed by the openers.
	 */
	clean_remaps = 0;
	close_safe(&mnt_ns_fd);
	cleanup_mnt_ns();

	ret = stop_usernsd();
	if (ret < 0)
		goto out_kill;

	ret = move_veth_to_bridge();
	if (ret < 0)
		goto out_kill;

	ret = prepare_cgroup_properties();
	if (ret < 0)
		goto out_kill;

	ret = run_scripts(ACT_POST_RESTORE);
	if (ret != 0) {
		pr_err("Aborting restore due to post-restore script ret code %d\n", ret);
		timing_stop(TIME_RESTORE);
		write_stats(RESTORE_STATS);
		goto out_kill;
	}

	/* Unlock network before disabling repair mode on sockets */
	network_unlock();

	/*
	 * Stop getting sigchld, after we resume the tasks they
	 * may start to exit poking criu in vain.
	 */
	ignore_kids();

	/*
	 * -------------------------------------------------------------
	 * Below this line nothing should fail, because network is unlocked
	 */
	attach_to_tasks(root_as_sibling);

	ret = restore_switch_stage(CR_STATE_RESTORE_CREDS);
	BUG_ON(ret);

	timing_stop(TIME_RESTORE);

	ret = catch_tasks(root_as_sibling, &flag);

	pr_info("Restore finished successfully. Resuming tasks.\n");
	futex_set_and_wake(&task_entries->start, CR_STATE_COMPLETE);

	if (ret == 0)
		ret = parasite_stop_on_syscall(task_entries->nr_threads,
						__NR_rt_sigreturn, flag);

	if (clear_breakpoints())
		pr_err("Unable to flush breakpoints\n");

	if (ret == 0)
		finalize_restore();

	if (restore_freezer_state())
		pr_err("Unable to restore freezer state\n");

	fini_cgroup();

	/* Detaches from processes and they continue run through sigreturn. */
	finalize_restore_detach(ret);

	write_stats(RESTORE_STATS);

	if (!opts.restore_detach && !opts.exec_cmd)
		wait(NULL);

	return 0;

out_kill:
	/*
	 * The processes can be killed only when all of them have been created,
	 * otherwise an external proccesses can be killed.
	 */
	if (root_ns_mask & CLONE_NEWPID) {
		int status;

		/* Kill init */
		if (root_item->pid.real > 0)
			kill(root_item->pid.real, SIGKILL);

		if (waitpid(root_item->pid.real, &status, 0) < 0)
			pr_warn("Unable to wait %d: %s",
				root_item->pid.real, strerror(errno));
	} else {
		struct pstree_item *pi;

		for_each_pstree_item(pi)
			if (pi->pid.virt > 0)
				kill(pi->pid.virt, SIGKILL);
	}

	if (opts.pidfile) {
		if (unlink(opts.pidfile))
			pr_perror("Unable to remove %s", opts.pidfile);
	}
out:
	fini_cgroup();
	if (clean_remaps)
		try_clean_remaps(mnt_ns_fd);
	cleanup_mnt_ns();
	stop_usernsd();
	__restore_switch_stage(CR_STATE_FAIL);
	pr_err("Restoring FAILED.\n");
	return -1;
}

static int prepare_task_entries(void)
{
	task_entries_pos = rst_mem_align_cpos(RM_SHREMAP);
	task_entries = rst_mem_alloc(sizeof(*task_entries), RM_SHREMAP);
	if (!task_entries) {
		pr_perror("Can't map shmem");
		return -1;
	}

	task_entries->nr_threads = 0;
	task_entries->nr_tasks = 0;
	task_entries->nr_helpers = 0;
	atomic_set(&task_entries->nr_zombies, 0);
	futex_set(&task_entries->start, CR_STATE_RESTORE_NS);
	mutex_init(&task_entries->userns_sync_lock);

	return 0;
}

int cr_restore_tasks(void)
{
	int ret = -1;

	if (cr_plugin_init(CR_PLUGIN_STAGE__RESTORE))
		return -1;

	if (check_img_inventory() < 0)
		goto err;

	if (init_stats(RESTORE_STATS))
		goto err;

	if (kerndat_init_rst())
		goto err;

	timing_start(TIME_RESTORE);

	if (cpu_init() < 0)
		goto err;

	if (vdso_init())
		goto err;

	if (opts.cpu_cap & (CPU_CAP_INS | CPU_CAP_CPU)) {
		if (cpu_validate_cpuinfo())
			goto err;
	}

	if (prepare_task_entries() < 0)
		goto err;

	if (prepare_pstree() < 0)
		goto err;

	if (crtools_prepare_shared() < 0)
		goto err;

	if (criu_signals_setup() < 0)
		goto err;

	ret = restore_root_task(root_item);
err:
	cr_plugin_fini(CR_PLUGIN_STAGE__RESTORE, ret);
	return ret;
}

static long restorer_get_vma_hint(struct list_head *tgt_vma_list,
		struct list_head *self_vma_list, long vma_len)
{
	struct vma_area *t_vma, *s_vma;
	long prev_vma_end = 0;
	struct vma_area end_vma;
	VmaEntry end_e;

	end_vma.e = &end_e;
	end_e.start = end_e.end = kdat.task_size;
	prev_vma_end = PAGE_SIZE * 0x10; /* CONFIG_LSM_MMAP_MIN_ADDR=65536 */

	s_vma = list_first_entry(self_vma_list, struct vma_area, list);
	t_vma = list_first_entry(tgt_vma_list, struct vma_area, list);

	while (1) {
		if (prev_vma_end + vma_len > s_vma->e->start) {
			if (s_vma->list.next == self_vma_list) {
				s_vma = &end_vma;
				continue;
			}
			if (s_vma == &end_vma)
				break;
			if (prev_vma_end < s_vma->e->end)
				prev_vma_end = s_vma->e->end;
			s_vma = list_entry(s_vma->list.next, struct vma_area, list);
			continue;
		}

		if (prev_vma_end + vma_len > t_vma->e->start) {
			if (t_vma->list.next == tgt_vma_list) {
				t_vma = &end_vma;
				continue;
			}
			if (t_vma == &end_vma)
				break;
			if (prev_vma_end < t_vma->e->end)
				prev_vma_end = t_vma->e->end;
			t_vma = list_entry(t_vma->list.next, struct vma_area, list);
			continue;
		}

		return prev_vma_end;
	}

	return -1;
}

static inline int timeval_valid(struct timeval *tv)
{
	return (tv->tv_sec >= 0) && ((unsigned long)tv->tv_usec < USEC_PER_SEC);
}

static inline int decode_itimer(char *n, ItimerEntry *ie, struct itimerval *val)
{
	if (ie->isec == 0 && ie->iusec == 0) {
		memzero_p(val);
		return 0;
	}

	val->it_interval.tv_sec = ie->isec;
	val->it_interval.tv_usec = ie->iusec;

	if (!timeval_valid(&val->it_interval)) {
		pr_err("Invalid timer interval\n");
		return -1;
	}

	if (ie->vsec == 0 && ie->vusec == 0) {
		/*
		 * Remaining time was too short. Set it to
		 * interval to make the timer armed and work.
		 */
		val->it_value.tv_sec = ie->isec;
		val->it_value.tv_usec = ie->iusec;
	} else {
		val->it_value.tv_sec = ie->vsec;
		val->it_value.tv_usec = ie->vusec;
	}

	if (!timeval_valid(&val->it_value)) {
		pr_err("Invalid timer value\n");
		return -1;
	}

	pr_info("Restored %s timer to %ld.%ld -> %ld.%ld\n", n,
			val->it_value.tv_sec, val->it_value.tv_usec,
			val->it_interval.tv_sec, val->it_interval.tv_usec);

	return 0;
}

/*
 * Legacy itimers restore from CR_FD_ITIMERS
 */

static int prepare_itimers_from_fd(int pid, struct task_restore_args *args)
{
	int ret = -1;
	struct cr_img *img;
	ItimerEntry *ie;

	img = open_image(CR_FD_ITIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("real", ie, &args->itimers[0]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("virt", ie, &args->itimers[1]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(img, &ie, PB_ITIMER);
	if (ret < 0)
		goto out;
	ret = decode_itimer("prof", ie, &args->itimers[2]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;
out:
	close_image(img);
	return ret;
}

static int prepare_itimers(int pid, CoreEntry *core, struct task_restore_args *args)
{
	int ret = 0;
	TaskTimersEntry *tte = core->tc->timers;

	if (!tte)
		return prepare_itimers_from_fd(pid, args);

	ret |= decode_itimer("real", tte->real, &args->itimers[0]);
	ret |= decode_itimer("virt", tte->virt, &args->itimers[1]);
	ret |= decode_itimer("prof", tte->prof, &args->itimers[2]);

	return ret;
}

static inline int timespec_valid(struct timespec *ts)
{
	return (ts->tv_sec >= 0) && ((unsigned long)ts->tv_nsec < NSEC_PER_SEC);
}

static inline int decode_posix_timer(PosixTimerEntry *pte,
		struct restore_posix_timer *pt)
{
	pt->val.it_interval.tv_sec = pte->isec;
	pt->val.it_interval.tv_nsec = pte->insec;

	if (!timespec_valid(&pt->val.it_interval)) {
		pr_err("Invalid timer interval(posix)\n");
		return -1;
	}

	if (pte->vsec == 0 && pte->vnsec == 0) {
		// Remaining time was too short. Set it to
		// interval to make the timer armed and work.
		pt->val.it_value.tv_sec = pte->isec;
		pt->val.it_value.tv_nsec = pte->insec;
	} else {
		pt->val.it_value.tv_sec = pte->vsec;
		pt->val.it_value.tv_nsec = pte->vnsec;
	}

	if (!timespec_valid(&pt->val.it_value)) {
		pr_err("Invalid timer value(posix)\n");
		return -1;
	}

	pt->spt.it_id = pte->it_id;
	pt->spt.clock_id = pte->clock_id;
	pt->spt.si_signo = pte->si_signo;
	pt->spt.it_sigev_notify = pte->it_sigev_notify;
	pt->spt.sival_ptr = decode_pointer(pte->sival_ptr);
	pt->overrun = pte->overrun;

	return 0;
}

static int cmp_posix_timer_proc_id(const void *p1, const void *p2)
{
	return ((struct restore_posix_timer *)p1)->spt.it_id - ((struct restore_posix_timer *)p2)->spt.it_id;
}

static unsigned long posix_timers_cpos;
static unsigned int posix_timers_nr;

static void sort_posix_timers(void)
{
	/*
	 * This is required for restorer's create_posix_timers(),
	 * it will probe them one-by-one for the desired ID, since
	 * kernel doesn't provide another API for timer creation
	 * with given ID.
	 */

	if (posix_timers_nr > 0)
		qsort(rst_mem_remap_ptr(posix_timers_cpos, RM_PRIVATE),
				posix_timers_nr,
				sizeof(struct restore_posix_timer),
				cmp_posix_timer_proc_id);
}

/*
 * Legacy posix timers restoration from CR_FD_POSIX_TIMERS
 */

static int prepare_posix_timers_from_fd(int pid)
{
	struct cr_img *img;
	int ret = -1;
	struct restore_posix_timer *t;

	img = open_image(CR_FD_POSIX_TIMERS, O_RSTR, pid);
	if (!img)
		return -1;

	while (1) {
		PosixTimerEntry *pte;

		ret = pb_read_one_eof(img, &pte, PB_POSIX_TIMER);
		if (ret <= 0)
			break;

		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			break;

		ret = decode_posix_timer(pte, t);
		if (ret < 0)
			break;

		posix_timer_entry__free_unpacked(pte, NULL);
		posix_timers_nr++;
	}

	close_image(img);
	if (!ret)
		sort_posix_timers();

	return ret;
}

static int prepare_posix_timers(int pid, CoreEntry *core)
{
	int i, ret = -1;
	TaskTimersEntry *tte = core->tc->timers;
	struct restore_posix_timer *t;

	posix_timers_cpos = rst_mem_align_cpos(RM_PRIVATE);

	if (!tte)
		return prepare_posix_timers_from_fd(pid);

	posix_timers_nr = tte->n_posix;
	for (i = 0; i < posix_timers_nr; i++) {
		t = rst_mem_alloc(sizeof(struct restore_posix_timer), RM_PRIVATE);
		if (!t)
			goto out;

		if (decode_posix_timer(tte->posix[i], t))
			goto out;
	}

	ret = 0;
	sort_posix_timers();
out:
	return ret;
}

static inline int verify_cap_size(CredsEntry *ce)
{
	return ((ce->n_cap_inh == CR_CAP_SIZE) && (ce->n_cap_eff == CR_CAP_SIZE) &&
		(ce->n_cap_prm == CR_CAP_SIZE) && (ce->n_cap_bnd == CR_CAP_SIZE));
}

static int prepare_mm(pid_t pid, struct task_restore_args *args)
{
	int exe_fd, i, ret = -1;
	MmEntry *mm = rsti(current)->mm;

	args->mm = *mm;
	args->mm.n_mm_saved_auxv = 0;
	args->mm.mm_saved_auxv = NULL;

	if (mm->n_mm_saved_auxv > AT_VECTOR_SIZE) {
		pr_err("Image corrupted on pid %d\n", pid);
		goto out;
	}

	args->mm_saved_auxv_size = mm->n_mm_saved_auxv*sizeof(auxv_t);
	for (i = 0; i < mm->n_mm_saved_auxv; ++i) {
		args->mm_saved_auxv[i] = (auxv_t)mm->mm_saved_auxv[i];
	}

	exe_fd = open_reg_by_id(mm->exe_file_id);
	if (exe_fd < 0)
		goto out;

	args->fd_exe_link = exe_fd;
	ret = 0;
out:
	return ret;
}

static void *restorer;
static unsigned long restorer_len;

static int prepare_restorer_blob(void)
{
	/*
	 * We map anonymous mapping, not mremap the restorer itself later.
	 * Otherwise the restorer vma would be tied to criu binary which
	 * in turn will lead to set-exe-file prctl to fail with EBUSY.
	 */

	restorer_len = pie_size(restorer_blob);
	restorer = mmap(NULL, restorer_len,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANON, 0, 0);
	if (restorer == MAP_FAILED) {
		pr_perror("Can't map restorer code");
		return -1;
	}

	memcpy(restorer, &restorer_blob, sizeof(restorer_blob));
	return 0;
}

static int remap_restorer_blob(void *addr)
{
	void *mem;

	mem = mremap(restorer, restorer_len, restorer_len,
			MREMAP_FIXED | MREMAP_MAYMOVE, addr);
	if (mem != addr) {
		pr_perror("Can't remap restorer blob");
		return -1;
	}

	ELF_RELOCS_APPLY_RESTORER(addr, addr);
	return 0;
}

static int validate_sched_parm(struct rst_sched_param *sp)
{
	if ((sp->nice < -20) || (sp->nice > 19))
		return 0;

	switch (sp->policy) {
	case SCHED_RR:
	case SCHED_FIFO:
		return ((sp->prio > 0) && (sp->prio < 100));
	case SCHED_IDLE:
	case SCHED_OTHER:
	case SCHED_BATCH:
		return sp->prio == 0;
	}

	return 0;
}

static int prep_sched_info(struct rst_sched_param *sp, ThreadCoreEntry *tc)
{
	if (!tc->has_sched_policy) {
		sp->policy = SCHED_OTHER;
		sp->nice = 0;
		return 0;
	}

	sp->policy = tc->sched_policy;
	sp->nice = tc->sched_nice;
	sp->prio = tc->sched_prio;

	if (!validate_sched_parm(sp)) {
		pr_err("Inconsistent sched params received (%d.%d.%d)\n",
				sp->policy, sp->nice, sp->prio);
		return -1;
	}

	return 0;
}

static unsigned long decode_rlim(u_int64_t ival)
{
	return ival == -1 ? RLIM_INFINITY : ival;
}

static unsigned long rlims_cpos;
static unsigned int rlims_nr;

/*
 * Legacy rlimits restore from CR_FD_RLIMIT
 */

static int prepare_rlimits_from_fd(int pid)
{
	struct rlimit *r;
	int ret;
	struct cr_img *img;

	/*
	 * Old image -- read from the file.
	 */
	img = open_image(CR_FD_RLIMIT, O_RSTR, pid);
	if (!img)
		return -1;

	while (1) {
		RlimitEntry *re;

		ret = pb_read_one_eof(img, &re, PB_RLIMIT);
		if (ret <= 0)
			break;

		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n",
			       rlims_nr);
			return -1;
		}

		r->rlim_cur = decode_rlim(re->cur);
		r->rlim_max = decode_rlim(re->max);
		if (r->rlim_cur > r->rlim_max) {
			pr_err("Can't restore cur > max for %d.%d\n",
					pid, rlims_nr);
			r->rlim_cur = r->rlim_max;
		}

		rlimit_entry__free_unpacked(re, NULL);

		rlims_nr++;
	}

	close_image(img);

	return 0;
}

static int prepare_rlimits(int pid, CoreEntry *core)
{
	int i;
	TaskRlimitsEntry *rls = core->tc->rlimits;
	struct rlimit *r;

	rlims_cpos = rst_mem_align_cpos(RM_PRIVATE);

	if (!rls)
		return prepare_rlimits_from_fd(pid);

	for (i = 0; i < rls->n_rlimits; i++) {
		r = rst_mem_alloc(sizeof(*r), RM_PRIVATE);
		if (!r) {
			pr_err("Can't allocate memory for resource %d\n", i);
			return -1;
		}

		r->rlim_cur = decode_rlim(rls->rlimits[i]->cur);
		r->rlim_max = decode_rlim(rls->rlimits[i]->max);

		if (r->rlim_cur > r->rlim_max) {
			pr_warn("Can't restore cur > max for %d.%d\n", pid, i);
			r->rlim_cur = r->rlim_max;
		}
	}

	rlims_nr = rls->n_rlimits;
	return 0;
}

static int signal_to_mem(SiginfoEntry *sie)
{
	siginfo_t *info, *t;

	info = (siginfo_t *) sie->siginfo.data;
	t = rst_mem_alloc(sizeof(siginfo_t), RM_PRIVATE);
	if (!t)
		return -1;

	memcpy(t, info, sizeof(*info));

	return 0;
}

static int open_signal_image(int type, pid_t pid, unsigned int *nr)
{
	int ret;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (!img)
		return -1;

	*nr = 0;
	while (1) {
		SiginfoEntry *sie;

		ret = pb_read_one_eof(img, &sie, PB_SIGINFO);
		if (ret <= 0)
			break;
		if (sie->siginfo.len != sizeof(siginfo_t)) {
			pr_err("Unknown image format\n");
			ret = -1;
			break;
		}

		ret = signal_to_mem(sie);
		if (ret)
			break;

		(*nr)++;

		siginfo_entry__free_unpacked(sie, NULL);
	}

	close_image(img);

	return ret ? : 0;
}

static int prepare_one_signal_queue(SignalQueueEntry *sqe, unsigned int *nr)
{
	int i;

	for (i = 0; i < sqe->n_signals; i++)
		if (signal_to_mem(sqe->signals[i]))
			return -1;

	*nr = sqe->n_signals;

	return 0;
}

static unsigned long siginfo_cpos;
static unsigned int siginfo_nr, *siginfo_priv_nr;

static int prepare_signals(int pid, CoreEntry *leader_core)
{
	int ret = -1, i;

	siginfo_cpos = rst_mem_align_cpos(RM_PRIVATE);
	siginfo_priv_nr = xmalloc(sizeof(int) * current->nr_threads);
	if (siginfo_priv_nr == NULL)
		goto out;

	/* Prepare shared signals */
	if (!leader_core->tc->signals_s)/*backward compatibility*/
		ret = open_signal_image(CR_FD_SIGNAL, pid, &siginfo_nr);
	else
		ret = prepare_one_signal_queue(leader_core->tc->signals_s, &siginfo_nr);

	if (ret < 0)
		goto out;

	for (i = 0; i < current->nr_threads; i++) {
		if (!current->core[i]->thread_core->signals_p)/*backward compatibility*/
			ret = open_signal_image(CR_FD_PSIGNAL,
					current->threads[i].virt, &siginfo_priv_nr[i]);
		else
			ret = prepare_one_signal_queue(current->core[i]->thread_core->signals_p,
										&siginfo_priv_nr[i]);
		if (ret < 0)
			goto out;
	}
out:
	return ret;
}

extern void __gcov_flush(void) __attribute__((weak));
void __gcov_flush(void) {}

static void rst_reloc_creds(struct thread_restore_args *thread_args,
			    unsigned long *creds_pos_next)
{
	struct thread_creds_args *args;

	if (unlikely(!*creds_pos_next))
		return;

	args = rst_mem_remap_ptr(*creds_pos_next, RM_PRIVATE);

	if (args->lsm_profile)
		args->lsm_profile = rst_mem_remap_ptr(args->mem_lsm_profile_pos, RM_PRIVATE);
	if (args->groups)
		args->groups = rst_mem_remap_ptr(args->mem_groups_pos, RM_PRIVATE);

	*creds_pos_next = args->mem_pos_next;
	thread_args->creds_args = args;
}

static struct thread_creds_args *
rst_prep_creds_args(CredsEntry *ce, unsigned long *prev_pos)
{
	unsigned long this_pos;
	struct thread_creds_args *args;

	if (!verify_cap_size(ce)) {
		pr_err("Caps size mismatch %d %d %d %d\n",
		       (int)ce->n_cap_inh, (int)ce->n_cap_eff,
		       (int)ce->n_cap_prm, (int)ce->n_cap_bnd);
		return ERR_PTR(-EINVAL);
	}

	this_pos = rst_mem_align_cpos(RM_PRIVATE);

	args = rst_mem_alloc(sizeof(*args), RM_PRIVATE);
	if (!args)
		return ERR_PTR(-ENOMEM);

	args->cap_last_cap = kdat.last_cap;
	memcpy(&args->creds, ce, sizeof(args->creds));

	if (ce->lsm_profile || opts.lsm_supplied) {
		char *rendered = NULL, *profile;

		profile = ce->lsm_profile;
		if (opts.lsm_supplied)
			profile = opts.lsm_profile;

		if (validate_lsm(profile) < 0)
			return ERR_PTR(-EINVAL);

		if (profile && render_lsm_profile(profile, &rendered)) {
			return ERR_PTR(-EINVAL);
		}

		if (rendered) {
			size_t lsm_profile_len;
			char *lsm_profile;

			args->mem_lsm_profile_pos = rst_mem_align_cpos(RM_PRIVATE);
			lsm_profile_len = strlen(rendered);
			lsm_profile = rst_mem_alloc(lsm_profile_len + 1, RM_PRIVATE);
			if (!lsm_profile) {
				xfree(rendered);
				return ERR_PTR(-ENOMEM);
			}

			args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
			args->lsm_profile = lsm_profile;
			strncpy(args->lsm_profile, rendered, lsm_profile_len);
			xfree(rendered);
		}
	} else {
		args->lsm_profile = NULL;
		args->mem_lsm_profile_pos = 0;
	}

	/*
	 * Zap fields which we cant use.
	 */
	args->creds.cap_inh = NULL;
	args->creds.cap_eff = NULL;
	args->creds.cap_prm = NULL;
	args->creds.cap_bnd = NULL;
	args->creds.groups = NULL;
	args->creds.lsm_profile = NULL;

	memcpy(args->cap_inh, ce->cap_inh, sizeof(args->cap_inh));
	memcpy(args->cap_eff, ce->cap_eff, sizeof(args->cap_eff));
	memcpy(args->cap_prm, ce->cap_prm, sizeof(args->cap_prm));
	memcpy(args->cap_bnd, ce->cap_bnd, sizeof(args->cap_bnd));

	if (ce->n_groups) {
		unsigned int *groups;

		args->mem_groups_pos = rst_mem_align_cpos(RM_PRIVATE);
		groups = rst_mem_alloc(ce->n_groups * sizeof(u32), RM_PRIVATE);
		if (!groups)
			return ERR_PTR(-ENOMEM);
		args = rst_mem_remap_ptr(this_pos, RM_PRIVATE);
		args->groups = groups;
		memcpy(args->groups, ce->groups, ce->n_groups * sizeof(u32));
	} else {
		args->groups = NULL;
		args->mem_groups_pos = 0;
	}

	args->mem_pos_next = 0;

	if (prev_pos) {
		if (*prev_pos) {
			struct thread_creds_args *prev;

			prev = rst_mem_remap_ptr(*prev_pos, RM_PRIVATE);
			prev->mem_pos_next = this_pos;
		}
		*prev_pos = this_pos;
	}
	return args;
}

static int rst_prep_creds_from_img(pid_t pid)
{
	CredsEntry *ce = NULL;
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_CREDS, O_RSTR, pid);
	if (!img)
		return -ENOENT;

	ret = pb_read_one(img, &ce, PB_CREDS);
	close_image(img);

	if (ret > 0) {
		struct thread_creds_args *args;

		args = rst_prep_creds_args(ce, NULL);
		if (IS_ERR(args))
			ret = PTR_ERR(args);
		else
			ret = 0;
	}
	creds_entry__free_unpacked(ce, NULL);
	return ret;
}

static int rst_prep_creds(pid_t pid, CoreEntry *core, unsigned long *creds_pos)
{
	struct thread_creds_args *args = NULL;
	unsigned long this_pos = 0;
	size_t i;

	/*
	 * This is _really_ very old image
	 * format where @thread_core were not
	 * present. It means we don't have
	 * creds either, just ignore and exit
	 * early.
	 */
	if (unlikely(!core->thread_core)) {
		*creds_pos = 0;
		return 0;
	}

	*creds_pos = rst_mem_align_cpos(RM_PRIVATE);

	/*
	 * Old format: one Creds per task carried in own image file.
	 */
	if (!core->thread_core->creds)
		return rst_prep_creds_from_img(pid);

	for (i = 0; i < current->nr_threads; i++) {
		CredsEntry *ce = current->core[i]->thread_core->creds;

		args = rst_prep_creds_args(ce, &this_pos);
		if (IS_ERR(args))
			return PTR_ERR(args);
	}

	return 0;
}

static int sigreturn_restore(pid_t pid, CoreEntry *core)
{
	void *mem = MAP_FAILED;
	void *restore_thread_exec_start;
	void *restore_task_exec_start;

	long new_sp, exec_mem_hint;
	long ret;

	long restore_bootstrap_len;
	long rst_mem_size;

	struct task_restore_args *task_args;
	struct thread_restore_args *thread_args;
	long args_len;

	struct vma_area *vma;
	unsigned long tgt_vmas;

#ifdef CONFIG_VDSO
	unsigned long vdso_rt_size = 0;
	unsigned long vdso_rt_delta = 0;
#endif

	unsigned long aio_rings;
	MmEntry *mm = rsti(current)->mm;

	int n_seccomp_filters = 0;
	unsigned long seccomp_filter_pos = 0;

	struct vm_area_list self_vmas;
	struct vm_area_list *vmas = &rsti(current)->vmas;
	int i;

	unsigned long creds_pos = 0;
	unsigned long creds_pos_next;

	pr_info("Restore via sigreturn\n");

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);

	args_len = round_up(sizeof(*task_args) + sizeof(*thread_args) * current->nr_threads, page_size());
	pr_info("%d threads require %ldK of memory\n",
			current->nr_threads, KBYTES(args_len));

	/*
	 * Copy VMAs to private rst memory so that it's able to
	 * walk them and m(un|re)map.
	 */

	tgt_vmas = rst_mem_align_cpos(RM_PRIVATE);
	list_for_each_entry(vma, &vmas->h, list) {
		VmaEntry *vme;

		vme = rst_mem_alloc(sizeof(*vme), RM_PRIVATE);
		if (!vme)
			goto err_nv;

		*vme = *vma->e;

		if (vma_area_is_private(vma, kdat.task_size))
			vma_premmaped_start(vme) = vma->premmaped_addr;
	}

	/*
	 * Put info about AIO rings, they will get remapped
	 */

	aio_rings = rst_mem_align_cpos(RM_PRIVATE);
	for (i = 0; i < mm->n_aios; i++) {
		struct rst_aio_ring *raio;

		raio = rst_mem_alloc(sizeof(*raio), RM_PRIVATE);
		if (!raio)
			goto err_nv;

		raio->addr = mm->aios[i]->id;
		raio->nr_req = mm->aios[i]->nr_req;
		raio->len = mm->aios[i]->ring_len;
	}

	/*
	 * Get all the tcp sockets fds into rst memory -- restorer
	 * will turn repair off before going sigreturn
	 */
	if (rst_tcp_socks_prep())
		goto err_nv;

	/*
	 * Copy timerfd params for restorer args, we need to proceed
	 * timer setting at the very late.
	 */
	if (rst_timerfd_prep())
		goto err_nv;

	/*
	 * Read creds info for every thread and allocate memory
	 * needed so we can use this data inside restorer.
	 */
	if (rst_prep_creds(pid, core, &creds_pos))
		goto err_nv;

	/*
	 * We're about to search for free VM area and inject the restorer blob
	 * into it. No irrelevent mmaps/mremaps beyond this point, otherwise
	 * this unwanted mapping might get overlapped by the restorer.
	 */

	ret = parse_self_maps_lite(&self_vmas);
	if (ret < 0)
		goto err;

	if (seccomp_filters_get_rst_pos(core, &n_seccomp_filters, &seccomp_filter_pos) < 0)
		goto err;

	rst_mem_size = rst_mem_lock();
	restore_bootstrap_len = restorer_len + args_len + rst_mem_size;

#ifdef CONFIG_VDSO
	/*
	 * Figure out how much memory runtime vdso and vvar will need.
	 */
	vdso_rt_size = vdso_vma_size(&vdso_sym_rt);
	if (vdso_rt_size) {
		vdso_rt_delta = ALIGN(restore_bootstrap_len, PAGE_SIZE) - restore_bootstrap_len;
		vdso_rt_size += vdso_rt_delta;
		if (vvar_vma_size(&vdso_sym_rt))
			vdso_rt_size += ALIGN(vvar_vma_size(&vdso_sym_rt), PAGE_SIZE);
	}

	restore_bootstrap_len += vdso_rt_size;
#endif

	/*
	 * Restorer is a blob (code + args) that will get mapped in some
	 * place, that should _not_ intersect with both -- current mappings
	 * and mappings of the task we're restoring here. The subsequent
	 * call finds the start address for the restorer.
	 *
	 * After the start address is found we populate it with the restorer
	 * parts one by one (some are remap-ed, some are mmap-ed and copied
	 * or inited from scratch).
	 */

	exec_mem_hint = restorer_get_vma_hint(&vmas->h, &self_vmas.h,
					      restore_bootstrap_len);
	if (exec_mem_hint == -1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n",
		       restore_bootstrap_len);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: 0x%lx (needs ~%ldK)\n", exec_mem_hint,
			KBYTES(restore_bootstrap_len));

	ret = remap_restorer_blob((void *)exec_mem_hint);
	if (ret < 0)
		goto err;

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	restore_thread_exec_start	= restorer_sym(exec_mem_hint, arch_export_restore_thread);
	restore_task_exec_start		= restorer_sym(exec_mem_hint, arch_export_restore_task);
	rsti(current)->munmap_restorer	= restorer_sym(exec_mem_hint, arch_export_unmap);

	exec_mem_hint += restorer_len;

	/* VMA we need to run task_restore code */
	mem = mmap((void *)exec_mem_hint, args_len,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (mem != (void *)exec_mem_hint) {
		pr_err("Can't mmap section for restore code\n");
		goto err;
	}

	exec_mem_hint -= restorer_len;

	memzero(mem, args_len);
	task_args	= mem;
	thread_args	= (struct thread_restore_args *)(task_args + 1);

	task_args->proc_fd = dup(get_service_fd(PROC_FD_OFF));
	if (task_args->proc_fd < 0) {
		pr_perror("can't dup proc fd");
		goto err;
	}

	/*
	 * Get a reference to shared memory area which is
	 * used to signal if shmem restoration complete
	 * from low-level restore code.
	 *
	 * This shmem area is mapped right after the whole area of
	 * sigreturn rt code. Note we didn't allocated it before
	 * but this area is taken into account for 'hint' memory
	 * address.
	 */

	mem += args_len;
	if (rst_mem_remap(mem))
		goto err;

	task_args->breakpoint = &rsti(current)->breakpoint;
	task_args->task_entries = rst_mem_remap_ptr(task_entries_pos, RM_SHREMAP);

	task_args->rst_mem = mem;
	task_args->rst_mem_size = rst_mem_size;

	task_args->bootstrap_start = (void *)exec_mem_hint;
	task_args->bootstrap_len = restore_bootstrap_len;

	task_args->premmapped_addr = (unsigned long)rsti(current)->premmapped_addr;
	task_args->premmapped_len = rsti(current)->premmapped_len;

	task_args->task_size = kdat.task_size;

#define remap_array(name, nr, cpos)	do {				\
		task_args->name##_n = nr;				\
		task_args->name = rst_mem_remap_ptr(cpos, RM_PRIVATE);	\
	} while (0)

	remap_array(vmas,	  vmas->nr, tgt_vmas);
	remap_array(posix_timers, posix_timers_nr, posix_timers_cpos);
	remap_array(timerfd,	  rst_timerfd_nr, rst_timerfd_cpos);
	remap_array(siginfo,	  siginfo_nr, siginfo_cpos);
	remap_array(tcp_socks,	  rst_tcp_socks_nr, rst_tcp_socks_cpos);
	remap_array(rings,	  mm->n_aios, aio_rings);
	remap_array(rlims,	  rlims_nr, rlims_cpos);
	remap_array(helpers,	  n_helpers, helpers_pos);
	remap_array(zombies,	  n_zombies, zombies_pos);
	remap_array(seccomp_filters,	n_seccomp_filters, seccomp_filter_pos);

#undef remap_array

	if (core->tc->has_seccomp_mode)
		task_args->seccomp_mode = core->tc->seccomp_mode;

	/*
	 * Arguments for task restoration.
	 */

	BUG_ON(core->mtype != CORE_ENTRY__MARCH);

	task_args->logfd	= log_get_fd();
	task_args->loglevel	= log_get_loglevel();
	task_args->sigchld_act	= sigchld_act;

	strncpy(task_args->comm, core->tc->comm, sizeof(task_args->comm));


	/*
	 * Fill up per-thread data.
	 */
	creds_pos_next = creds_pos;
	for (i = 0; i < current->nr_threads; i++) {
		CoreEntry *tcore;
		struct rt_sigframe *sigframe;

		thread_args[i].pid = current->threads[i].virt;
		thread_args[i].siginfo_n = siginfo_priv_nr[i];
		thread_args[i].siginfo = rst_mem_remap_ptr(siginfo_cpos, RM_PRIVATE);
		thread_args[i].siginfo += siginfo_nr;
		siginfo_nr += thread_args[i].siginfo_n;

		/* skip self */
		if (thread_args[i].pid == pid) {
			task_args->t = thread_args + i;
			tcore = core;
		} else
			tcore = current->core[i];

		if ((tcore->tc || tcore->ids) && thread_args[i].pid != pid) {
			pr_err("Thread has optional fields present %d\n",
			       thread_args[i].pid);
			ret = -1;
		}

		if (ret < 0) {
			pr_err("Can't read core data for thread %d\n",
			       thread_args[i].pid);
			goto err;
		}

		thread_args[i].ta		= task_args;
		thread_args[i].gpregs		= *CORE_THREAD_ARCH_INFO(tcore)->gpregs;
		thread_args[i].clear_tid_addr	= CORE_THREAD_ARCH_INFO(tcore)->clear_tid_addr;
		core_get_tls(tcore, &thread_args[i].tls);

		rst_reloc_creds(&thread_args[i], &creds_pos_next);

		if (tcore->thread_core) {
			thread_args[i].has_futex	= true;
			thread_args[i].futex_rla	= tcore->thread_core->futex_rla;
			thread_args[i].futex_rla_len	= tcore->thread_core->futex_rla_len;
			thread_args[i].pdeath_sig	= tcore->thread_core->pdeath_sig;
			if (tcore->thread_core->pdeath_sig > _KNSIG) {
				pr_err("Pdeath signal is too big\n");
				goto err;
			}

			ret = prep_sched_info(&thread_args[i].sp, tcore->thread_core);
			if (ret)
				goto err;
		}

		sigframe = (struct rt_sigframe *)thread_args[i].mem_zone.rt_sigframe;

		if (construct_sigframe(sigframe, sigframe, tcore))
			goto err;

		if (thread_args[i].pid != pid)
			core_entry__free_unpacked(tcore, NULL);

		pr_info("Thread %4d stack %8p rt_sigframe %8p\n",
				i, thread_args[i].mem_zone.stack,
				thread_args[i].mem_zone.rt_sigframe);

	}

#ifdef CONFIG_VDSO
	/*
	 * Restorer needs own copy of vdso parameters. Runtime
	 * vdso must be kept non intersecting with anything else,
	 * since we need it being accessible even when own
	 * self-vmas are unmaped.
	 */
	mem += rst_mem_size;
	task_args->vdso_rt_parked_at = (unsigned long)mem + vdso_rt_delta;
	task_args->vdso_sym_rt = vdso_sym_rt;
	task_args->vdso_rt_size = vdso_rt_size;
#endif

	new_sp = restorer_stack(task_args->t);

	ret = prepare_itimers(pid, core, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_mm(pid, task_args);
	if (ret < 0)
		goto err;

	/* No longer need it */
	core_entry__free_unpacked(core, NULL);
	xfree(current->core);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads		= current->nr_threads;
	task_args->clone_restore_fn	= (void *)restore_thread_exec_start;
	task_args->thread_args		= thread_args;

	/*
	 * Make root and cwd restore _that_ late not to break any
	 * attempts to open files by paths above (e.g. /proc).
	 */

	if (restore_fs(current))
		goto err;

	close_image_dir();
	close_proc();
	close_service_fd(ROOT_FD_OFF);
	close_service_fd(USERNSD_SK);

	__gcov_flush();

	pr_info("task_args: %p\n"
		"task_args->pid: %d\n"
		"task_args->nr_threads: %d\n"
		"task_args->clone_restore_fn: %p\n"
		"task_args->thread_args: %p\n",
		task_args, task_args->t->pid,
		task_args->nr_threads,
		task_args->clone_restore_fn,
		task_args->thread_args);

	/*
	 * An indirect call to task_restore, note it never returns
	 * and restoring core is extremely destructive.
	 */

	JUMP_TO_RESTORER_BLOB(new_sp, restore_task_exec_start, task_args);

err:
	free_mappings(&self_vmas);
err_nv:
	/* Just to be sure */
	exit(1);
	return -1;
}
