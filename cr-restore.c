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
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/mount.h>

#include <sched.h>

#include <sys/sendfile.h>

#include "compiler.h"
#include "asm/types.h"
#include "asm/restorer.h"

#include "image.h"
#include "util.h"
#include "log.h"
#include "syscall.h"
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
#include "shmem.h"
#include "mount.h"
#include "fsnotify.h"
#include "pstree.h"
#include "net.h"
#include "tty.h"
#include "cpu.h"
#include "file-lock.h"
#include "page-read.h"
#include "sysctl.h"
#include "vdso.h"

#include "protobuf.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/timer.pb-c.h"
#include "protobuf/vma.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/pagemap.pb-c.h"
#include "protobuf/siginfo.pb-c.h"

#include "asm/restore.h"

static struct pstree_item *current;

static int restore_task_with_children(void *);
static int sigreturn_restore(pid_t pid, CoreEntry *core);
static int prepare_restorer_blob(void);

static VM_AREA_LIST(rst_vmas); /* XXX .longest is NOT tracked for this guy */

static int shmem_remap(void *old_addr, void *new_addr, unsigned long size)
{
	void *ret;

	ret = mremap(old_addr, size, size,
			MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
	if (new_addr != ret) {
		pr_perror("mremap failed");
		return -1;
	}

	return 0;
}

static int crtools_prepare_shared(void)
{
	if (prepare_shared_fdinfo())
		return -1;

	/* Connections are unlocked from criu */
	if (collect_inet_sockets())
		return -1;

	if (tty_prep_fds())
		return -1;

	return 0;
}

static int root_prepare_shared(void)
{
	int ret = 0;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	if (prepare_shmem_restore())
		return -1;

	if (prepare_shared_tty())
		return -1;

	if (prepare_shared_reg_files())
		return -1;

	if (collect_reg_files())
		return -1;

	if (collect_ns_files())
		return -1;

	if (collect_pipes())
		return -1;

	if (collect_fifo())
		return -1;

	if (collect_unix_sockets())
		return -1;

	if (collect_packet_sockets())
		return -1;

	if (collect_netlink_sockets())
		return -1;

	if (collect_eventfd())
		return -1;

	if (collect_eventpoll())
		return -1;

	if (collect_signalfd())
		return -1;

	if (collect_inotify())
		return -1;

	if (collect_tty())
		return -1;

	for_each_pstree_item(pi) {
		if (pi->state == TASK_HELPER)
			continue;

		ret = prepare_shmem_pid(pi->pid.virt);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi);
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
static int map_private_vma(pid_t pid, struct vma_area *vma, void *tgt_addr,
			struct vma_area **pvma, struct list_head *pvma_list)
{
	int ret;
	void *addr, *paddr = NULL;
	unsigned long nr_pages;
	struct vma_area *p = *pvma;

	if (vma_entry_is(&vma->vma, VMA_FILE_PRIVATE)) {
		ret = get_filemap_fd(pid, &vma->vma);
		if (ret < 0) {
			pr_err("Can't fixup VMA's fd\n");
			return -1;
		}
		vma->vma.fd = ret;
		/* shmid will be used for a temporary address */
		vma->vma.shmid = 0;
	}

	nr_pages = vma_entry_len(&vma->vma) / PAGE_SIZE;
	vma->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
	if (vma->page_bitmap == NULL)
		return -1;

	list_for_each_entry_continue(p, pvma_list, list) {
		if (p->vma.start > vma->vma.start)
			 break;

		if (p->vma.end == vma->vma.end &&
		    p->vma.start == vma->vma.start) {
			pr_info("COW 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" vma\n",
				vma->vma.start, vma->vma.end, vma->vma.pgoff);
			paddr = decode_pointer(vma_premmaped_start(&p->vma));
			break;
		}

	}

	*pvma = p;

	if (paddr == NULL) {
		pr_info("Map 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" vma\n",
			vma->vma.start, vma->vma.end, vma->vma.pgoff);

		addr = mmap(tgt_addr, vma_entry_len(&vma->vma),
				vma->vma.prot | PROT_WRITE,
				vma->vma.flags | MAP_FIXED,
				vma->vma.fd, vma->vma.pgoff);

		if (addr == MAP_FAILED) {
			pr_perror("Unable to map ANON_VMA");
			return -1;
		}
	} else {
		vma->ppage_bitmap = p->page_bitmap;

		addr = mremap(paddr, vma_area_len(vma), vma_area_len(vma),
				MREMAP_FIXED | MREMAP_MAYMOVE, tgt_addr);
		if (addr != tgt_addr) {
			pr_perror("Unable to remap a private vma");
			return -1;
		}

	}

	vma_premmaped_start(&(vma->vma)) = (unsigned long) addr;
	pr_debug("\tpremap 0x%016"PRIx64"-0x%016"PRIx64" -> %016lx\n",
		vma->vma.start, vma->vma.end, (unsigned long)addr);

	if (vma_entry_is(&vma->vma, VMA_FILE_PRIVATE))
		close(vma->vma.fd);

	return 0;
}

static int restore_priv_vma_content(pid_t pid)
{
	struct vma_area *vma;
	int ret = 0;

	unsigned int nr_restored = 0;
	unsigned int nr_shared = 0;
	unsigned int nr_droped = 0;
	unsigned long va;
	struct page_read pr;

	vma = list_first_entry(&rst_vmas.h, struct vma_area, list);
	ret = open_page_read(pid, &pr);
	if (ret)
		return -1;

	/*
	 * Read page contents.
	 */
	while (1) {
		unsigned long off, i, nr_pages;;
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
			while (va >= vma->vma.end) {
				if (vma->list.next == &rst_vmas.h)
					goto err_addr;
				vma = list_entry(vma->list.next, struct vma_area, list);
			}

			/*
			 * Make sure the page address is inside existing VMA
			 * and the VMA it refers to still private one, since
			 * there is no guarantee that the data from pagemap is
			 * valid.
			 */
			if (va < vma->vma.start)
				goto err_addr;
			else if (unlikely(!vma_priv(&vma->vma))) {
				pr_err("Trying to restore page for non-private VMA\n");
				goto err_addr;
			}

			off = (va - vma->vma.start) / PAGE_SIZE;

			set_bit(off, vma->page_bitmap);
			if (vma->ppage_bitmap)
				clear_bit(off, vma->ppage_bitmap);

			ret = pr.read_page(&pr, va, buf);
			if (ret < 0)
				break;

			va += PAGE_SIZE;

			p = decode_pointer((off) * PAGE_SIZE +
					vma_premmaped_start(&vma->vma));

			if (memcmp(p, buf, PAGE_SIZE) == 0) {
				nr_shared++;
				continue;
			}

			memcpy(p, buf, PAGE_SIZE);
			nr_restored++;
		}

		if (pr.put_pagemap)
			pr.put_pagemap(&pr);
	}

	pr.close(&pr);
	if (ret < 0)
		return ret;

	/* Remove pages, which were not shared with a child */
	list_for_each_entry(vma, &rst_vmas.h, list) {
		unsigned long size, i = 0;
		void *addr = decode_pointer(vma_premmaped_start(&vma->vma));

		if (vma->ppage_bitmap == NULL)
			continue;

		size = vma_entry_len(&vma->vma) / PAGE_SIZE;
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

	pr_info("nr_restored_pages: %d\n", nr_restored);
	pr_info("nr_shared_pages:   %d\n", nr_shared);
	pr_info("nr_droped_pages:   %d\n", nr_droped);

	return 0;

err_addr:
	pr_err("Page entry address %lx outside of VMA %lx-%lx\n",
	       va, (long)vma->vma.start, (long)vma->vma.end);
	return -1;
}

static int read_vmas(int pid)
{
	int fd, ret = 0;
	LIST_HEAD(old);
	struct vma_area *pvma, *vma;
	unsigned long priv_size = 0;
	void *addr;

	void *old_premmapped_addr = NULL;
	unsigned long old_premmapped_len, pstart = 0;

	rst_vmas.nr = 0;
	list_replace_init(&rst_vmas.h, &old);

	/* Skip errors, because a zombie doesn't have an image of vmas */
	fd = open_image(CR_FD_VMAS, O_RSTR, pid);
	if (fd < 0) {
		if (errno != ENOENT)
			ret = fd;
		goto out;
	}

	while (1) {
		struct vma_area *vma;
		VmaEntry *e;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		ret = pb_read_one_eof(fd, &e, PB_VMAS);
		if (ret <= 0) {
			xfree(vma);
			break;
		}

		rst_vmas.nr++;
		list_add_tail(&vma->list, &rst_vmas.h);

		vma->vma = *e;
		vma_entry__free_unpacked(e, NULL);

		if (vma->vma.fd != -1) {
			ret = -1;
			pr_err("Error in vma->fd setting (%Ld)\n",
					(unsigned long long)vma->vma.fd);
			break;
		}

		if (!vma_priv(&vma->vma))
			continue;

		priv_size += vma_area_len(vma);
	}

	if (ret < 0)
		goto out;

	/* Reserve a place for mapping private vma-s one by one */
	addr = mmap(NULL, priv_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Unable to reserve memory (%lu bytes)", priv_size);
		return -1;
	}

	old_premmapped_addr = current->rst->premmapped_addr;
	old_premmapped_len = current->rst->premmapped_len;
	current->rst->premmapped_addr = addr;
	current->rst->premmapped_len = priv_size;

	pvma = list_entry(&old, struct vma_area, list);

	list_for_each_entry(vma, &rst_vmas.h, list) {
		if (pstart > vma->vma.start) {
			ret = -1;
			pr_err("VMA-s are not sorted in the image file\n");
			break;
		}
		pstart = vma->vma.start;

		if (!vma_priv(&vma->vma))
			continue;

		ret = map_private_vma(pid, vma, addr, &pvma, &old);
		if (ret < 0)
			break;

		addr += vma_area_len(vma);
	}

	if (ret == 0)
		ret = restore_priv_vma_content(pid);
	close(fd);

out:
	while (!list_empty(&old)) {
		vma = list_first_entry(&old, struct vma_area, list);
		list_del(&vma->list);
		xfree(vma);
	}

	if (old_premmapped_addr &&
	    munmap(old_premmapped_addr, old_premmapped_len)) {
		pr_perror("Unable to unmap %p(%lx)",
				old_premmapped_addr, old_premmapped_len);
		return -1;
	}


	return ret;
}

static int open_vmas(int pid)
{
	struct vma_area *vma;
	int ret = 0;

	list_for_each_entry(vma, &rst_vmas.h, list) {
		if (!(vma_entry_is(&vma->vma, VMA_AREA_REGULAR)))
			continue;

		pr_info("Opening 0x%016"PRIx64"-0x%016"PRIx64" 0x%016"PRIx64" (%x) vma\n",
				vma->vma.start, vma->vma.end,
				vma->vma.pgoff, vma->vma.status);

		if (vma_entry_is(&vma->vma, VMA_AREA_SYSVIPC))
			ret = vma->vma.shmid;
		else if (vma_entry_is(&vma->vma, VMA_ANON_SHARED))
			ret = get_shmem_fd(pid, &vma->vma);
		else if (vma_entry_is(&vma->vma, VMA_FILE_SHARED))
			ret = get_filemap_fd(pid, &vma->vma);
		else if (vma_entry_is(&vma->vma, VMA_AREA_SOCKET))
			ret = get_socket_fd(pid, &vma->vma);
		else
			continue;

		if (ret < 0) {
			pr_err("Can't fixup fd\n");
			break;
		}

		pr_info("\t`- setting %d as mapping fd\n", ret);
		vma->vma.fd = ret;
	}

	return ret < 0 ? -1 : 0;
}

static rt_sigaction_t sigchld_act;
static int prepare_sigactions(int pid)
{
	rt_sigaction_t act, oact;
	int fd_sigact;
	SaEntry *e;
	int sig;
	int ret = -1;

	fd_sigact = open_image(CR_FD_SIGACT, O_RSTR, pid);
	if (fd_sigact < 0)
		return -1;

	for (sig = 1; sig <= SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = pb_read_one_eof(fd_sigact, &e, PB_SIGACT);
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
		/*
		 * A pure syscall is used, because glibc
		 * sigaction overwrites se_restorer.
		 */
		ret = sys_sigaction(sig, &act, &oact, sizeof(k_rtsigset_t));
		if (ret == -1) {
			pr_err("%d: Can't restore sigaction: %m\n", pid);
			goto err;
		}
	}

err:
	close_safe(&fd_sigact);
	return ret;
}

static int pstree_wait_helpers()
{
	struct pstree_item *pi;

	list_for_each_entry(pi, &current->children, sibling) {
		int status, ret;

		if (pi->state != TASK_HELPER)
			continue;

		/* Check, that a helper completed. */
		ret = waitpid(pi->pid.virt, &status, 0);
		if (ret == -1) {
			if (errno == ECHILD)
				continue; /* It has been waited in sigchld_handler */
			pr_err("waitpid(%d) failed\n", pi->pid.virt);
			return -1;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_err("%d exited with non-zero code (%d,%d)\n", pi->pid.virt,
				WEXITSTATUS(status), WTERMSIG(status));
			return -1;
		}

	}

	return 0;
}


static int restore_one_alive_task(int pid, CoreEntry *core)
{
	pr_info("Restoring resources\n");

	if (pstree_wait_helpers())
		return -1;

	if (prepare_fds(current))
		return -1;

	if (prepare_fs(pid))
		return -1;

	if (prepare_file_locks(pid))
		return -1;

	if (prepare_sigactions(pid))
		return -1;

	log_closedir();

	if (open_vmas(pid))
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

static int restore_one_fake(void)
{
	/* We should wait here, otherwise last_pid will be changed. */
	futex_wait_while(&task_entries->start, CR_STATE_FORKING);
	futex_wait_while(&task_entries->start, CR_STATE_RESTORE_PGID);
	return 0;
}

static int restore_one_zombie(int pid, int exit_code)
{
	pr_info("Restoring zombie with %d code\n", exit_code);

	if (task_entries != NULL) {
		restore_finish_stage(CR_STATE_RESTORE);
		zombie_prepare_signals();
		mutex_lock(&task_entries->zombie_lock);
	}

	if (exit_code & 0x7f) {
		int signr;

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(pid, signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int check_core(CoreEntry *core)
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
		if (!core->ids && !current->ids) {
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
	return ret < 0 ? ret : 0;
}

static int restore_one_task(int pid, CoreEntry *core)
{
	int ret;

	if (check_core(core)) {
		ret = -1;
		goto out;
	}

	switch ((int)core->tc->task_state) {
	case TASK_ALIVE:
		ret = restore_one_alive_task(pid, core);
		break;
	case TASK_DEAD:
		ret = restore_one_zombie(pid, core->tc->exit_code);
		break;
	default:
		pr_err("Unknown state in code %d\n", (int)core->tc->task_state);
		ret = -1;
		break;
	}

out:
	core_entry__free_unpacked(core, NULL);
	return ret;
}

/* All arguments should be above stack, because it grows down */
struct cr_clone_arg {
	char stack[PAGE_SIZE] __attribute__((aligned (8)));
	char stack_ptr[0];
	struct pstree_item *item;
	unsigned long clone_flags;
	int fd;

	CoreEntry *core;
};

static void write_pidfile(char *pfname, int pid)
{
	int fd;

	fd = open(pfname, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (fd == -1) {
		pr_perror("Can't open %s", pfname);
		kill(pid, SIGKILL);
		return;
	}

	dprintf(fd, "%d", pid);
	close(fd);
}

static inline int fork_with_pid(struct pstree_item *item)
{
	int ret = -1, fd;
	struct cr_clone_arg ca;
	pid_t pid = item->pid.virt;

	if (item->state != TASK_HELPER) {
		fd = open_image(CR_FD_CORE, O_RSTR, pid);
		if (fd < 0)
			return -1;

		ret = pb_read_one(fd, &ca.core, PB_CORE);
		close(fd);

		if (ret < 0)
			return -1;

		if (ca.core->tc->task_state == TASK_DEAD)
			item->parent->rst->nr_zombies++;
	} else
		ca.core = NULL;

	ca.item = item;
	ca.clone_flags = item->rst->clone_flags;

	pr_info("Forking task with %d pid (flags 0x%lx)\n", pid, ca.clone_flags);

	if (!(ca.clone_flags & CLONE_NEWPID)) {
		char buf[32];

		ca.fd = open(LAST_PID_PATH, O_RDWR);
		if (ca.fd < 0) {
			pr_perror("%d: Can't open %s", pid, LAST_PID_PATH);
			goto err;
		}

		if (flock(ca.fd, LOCK_EX)) {
			close(ca.fd);
			pr_perror("%d: Can't lock %s", pid, LAST_PID_PATH);
			goto err;
		}

		snprintf(buf, sizeof(buf), "%d", pid - 1);
		if (write_img_buf(ca.fd, buf, strlen(buf)))
			goto err_unlock;
	} else {
		ca.fd = -1;
		BUG_ON(pid != INIT_PID);
	}

	if (ca.clone_flags & CLONE_NEWNET)
		/*
		 * When restoring a net namespace we need to communicate
		 * with the original (i.e. -- init) one. Thus, prepare for
		 * that before we leave the existing namespaces.
		 */
		if (netns_pre_create())
			goto err_unlock;

	ret = clone(restore_task_with_children, ca.stack_ptr,
			ca.clone_flags | SIGCHLD, &ca);

	if (ret < 0)
		pr_perror("Can't fork for %d", pid);

	if (ca.clone_flags & CLONE_NEWPID)
		item->pid.real = ret;

	if (opts.pidfile && root_item == item)
		write_pidfile(opts.pidfile, ret);

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
	pid_t pgid;

	pr_info("Restoring %d to %d pgid\n", current->pid.virt, current->pgid);

	pgid = getpgrp();
	if (current->pgid == pgid)
		return;

	pr_info("\twill call setpgid, mine pgid is %d\n", pgid);
	if (setpgid(0, current->pgid) != 0) {
		pr_perror("Can't restore pgid (%d/%d->%d)", current->pid.virt, pgid, current->pgid);
		exit(1);
	}
}

static int mount_proc(void)
{
	int ret;
	char proc_mountpoint[] = "crtools-proc.XXXXXX";

	if (mkdtemp(proc_mountpoint) == NULL) {
		pr_perror("mkdtemp failed %s", proc_mountpoint);
		return -1;
	}

	pr_info("Mount procfs in %s\n", proc_mountpoint);
	if (mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL)) {
		pr_perror("mount failed");
		ret = -1;
		goto out_rmdir;
	}

	ret = set_proc_mountpoint(proc_mountpoint);

	if (umount2(proc_mountpoint, MNT_DETACH) == -1) {
		pr_perror("Can't umount %s", proc_mountpoint);
		return -1;
	}

out_rmdir:
	if (rmdir(proc_mountpoint) == -1) {
		pr_perror("Can't remove %s", proc_mountpoint);
		return -1;
	}

	return ret;
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	struct pstree_item *child;
	pid_t pid;
	int ret;
	sigset_t blockmask;

	current = ca->item;

	if ( !(ca->clone_flags & CLONE_FILES))
		close_safe(&ca->fd);

	if (current->state != TASK_HELPER) {
		ret = clone_service_fd(current->rst->service_fd_id);
		if (ret)
			exit(1);
	}

	pid = getpid();
	if (current->pid.virt != pid) {
		pr_err("Pid %d do not match expected %d\n", pid, current->pid.virt);
		exit(-1);
	}

	ret = log_init_by_pid();
	if (ret < 0)
		exit(1);

	/* Restore root task */
	if (current->parent == NULL) {
		if (collect_mount_info(getpid()))
			exit(1);

		if (prepare_namespace(current->pid.virt, ca->clone_flags))
			exit(1);

		/*
		 * We need non /proc proc mount for restoring pid and mount
		 * namespaces and do not care for the rest of the cases.
		 * Thus -- mount proc at custom location for any new namespace
		 */
		if (mount_proc())
			exit(1);

		restore_finish_stage(CR_STATE_RESTORE_NS);

		if (root_prepare_shared())
			exit(1);
	}

	/*
	 * The block mask will be restored in sigreturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);
	ret = sigprocmask(SIG_BLOCK, &blockmask, NULL);
	if (ret) {
		pr_perror("%d: Can't block signals", current->pid.virt);
		exit(1);
	}

	if (read_vmas(pid))
		exit(1);

	if ( !(ca->clone_flags & CLONE_FILES)) {
		ret = close_old_fds(current);
		if (ret)
			exit(1);
	}

	pr_info("Restoring children:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (!restore_before_setsid(child))
			continue;

		BUG_ON(child->born_sid != -1 && getsid(getpid()) != child->born_sid);

		ret = fork_with_pid(child);
		if (ret < 0)
			exit(1);
	}

	restore_sid();

	pr_info("Restoring children:\n");
	list_for_each_entry(child, &current->children, sibling) {
		if (restore_before_setsid(child))
			continue;
		ret = fork_with_pid(child);
		if (ret < 0)
			exit(1);
	}

	if (current->pgid == current->pid.virt)
		restore_pgid();

	restore_finish_stage(CR_STATE_FORKING);

	if (current->pgid != current->pid.virt)
		restore_pgid();

	if (current->state == TASK_HELPER)
		return restore_one_fake();

	restore_finish_stage(CR_STATE_RESTORE_PGID);
	return restore_one_task(current->pid.virt, ca->core);
}

static inline int stage_participants(int next_stage)
{
	switch (next_stage) {
	case CR_STATE_RESTORE_NS:
		return 1;
	case CR_STATE_FORKING:
		return task_entries->nr_tasks + task_entries->nr_helpers;
	case CR_STATE_RESTORE_PGID:
		return task_entries->nr_tasks;
	case CR_STATE_RESTORE:
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
	if (ret < 0)
		return ret;

	return 0;
}

static int restore_switch_stage(int next_stage)
{
	int ret;

	ret = restore_wait_inprogress_tasks();
	if (ret)
		return ret;

	futex_set(&task_entries->nr_in_progress,
			stage_participants(next_stage));
	futex_set_and_wake(&task_entries->start, next_stage);
	return 0;
}

static int restore_root_task(struct pstree_item *init)
{
	int ret;
	struct sigaction act, old_act;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, &old_act);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	if (init->pid.virt == INIT_PID) {
		if (!(current_ns_mask & CLONE_NEWPID)) {
			pr_err("This process tree can only be restored "
				"in a new pid namespace.\n"
				"criu should be re-executed with the "
				"\"--namespace pid\" option.\n");
			return -1;
		}
	} else	if (current_ns_mask & CLONE_NEWPID) {
		pr_err("Can't restore pid namespace without the process init\n");
		return -1;
	}

	futex_set(&task_entries->nr_in_progress,
			stage_participants(CR_STATE_RESTORE_NS));

	ret = fork_with_pid(init);
	if (ret < 0)
		return -1;

	pr_info("Wait until namespaces are created\n");
	ret = restore_wait_inprogress_tasks();
	if (ret)
		goto out;

	ret = run_scripts("setup-namespaces");
	if (ret)
		goto out;

	ret = restore_switch_stage(CR_STATE_FORKING);
	if (ret < 0)
		goto out;

	pr_info("Wait until all tasks are forked\n");
	ret = restore_switch_stage(CR_STATE_RESTORE_PGID);
	if (ret < 0)
		goto out;


	pr_info("Wait until all tasks restored pgid\n");
	ret = restore_switch_stage(CR_STATE_RESTORE);
	if (ret < 0)
		goto out;

	pr_info("Wait until all tasks restored sigchld handlers\n");
	ret = restore_switch_stage(CR_STATE_RESTORE_SIGCHLD);
	if (ret < 0)
		goto out;

	pr_info("Wait until all tasks are restored\n");
	ret = restore_switch_stage(CR_STATE_RESTORE_CREDS);
	if (ret < 0)
		goto out;

	futex_wait_until(&task_entries->nr_in_progress, 0);

	/* Restore SIGCHLD here to skip SIGCHLD from a network sctip */
	ret = sigaction(SIGCHLD, &old_act, NULL);
	if (ret < 0) {
		pr_perror("sigaction() failed");
		goto out;
	}

	network_unlock();
out:
	if (ret < 0) {
		struct pstree_item *pi;

		if (current_ns_mask & CLONE_NEWPID) {
			/* Kill init */
			if (root_item->pid.real > 0)
				kill(root_item->pid.real, SIGKILL);
		} else {
			for_each_pstree_item(pi)
				if (pi->pid.virt > 0)
					kill(pi->pid.virt, SIGKILL);
		}

		pr_err("Restoring FAILED.\n");
		return 1;
	}

	pr_info("Restore finished successfully. Resuming tasks.\n");
	futex_set_and_wake(&task_entries->start, CR_STATE_COMPLETE);

	if (!opts.restore_detach)
		wait(NULL);
	return 0;
}

static int prepare_task_entries()
{
	task_entries = mmap(NULL, TASK_ENTRIES_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (task_entries == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}
	task_entries->nr_threads = 0;
	task_entries->nr_tasks = 0;
	task_entries->nr_helpers = 0;
	futex_set(&task_entries->start, CR_STATE_RESTORE_NS);
	mutex_init(&task_entries->zombie_lock);

	return 0;
}

int cr_restore_tasks(void)
{
	if (check_img_inventory() < 0)
		return -1;

	if (cpu_init() < 0)
		return -1;

	if (vdso_init())
		return -1;

	if (prepare_task_entries() < 0)
		return -1;

	if (prepare_pstree() < 0)
		return -1;

	if (crtools_prepare_shared() < 0)
		return -1;

	return restore_root_task(root_item);
}

static long restorer_get_vma_hint(pid_t pid, struct list_head *tgt_vma_list,
		struct list_head *self_vma_list, long vma_len)
{
	struct vma_area *t_vma, *s_vma;
	long prev_vma_end = 0;
	struct vma_area end_vma;

	end_vma.vma.start = end_vma.vma.end = TASK_SIZE;
	prev_vma_end = PAGE_SIZE * 0x10; /* CONFIG_LSM_MMAP_MIN_ADDR=65536 */

	s_vma = list_first_entry(self_vma_list, struct vma_area, list);
	t_vma = list_first_entry(tgt_vma_list, struct vma_area, list);

	while (1) {
		if (prev_vma_end + vma_len > s_vma->vma.start) {
			if (s_vma->list.next == self_vma_list) {
				s_vma = &end_vma;
				continue;
			}
			if (s_vma == &end_vma)
				break;
			if (prev_vma_end < s_vma->vma.end)
				prev_vma_end = s_vma->vma.end;
			s_vma = list_entry(s_vma->list.next, struct vma_area, list);
			continue;
		}

		if (prev_vma_end + vma_len > t_vma->vma.start) {
			if (t_vma->list.next == tgt_vma_list) {
				t_vma = &end_vma;
				continue;
			}
			if (t_vma == &end_vma)
				break;
			if (prev_vma_end < t_vma->vma.end)
				prev_vma_end = t_vma->vma.end;
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

static inline int itimer_restore_and_fix(char *n, ItimerEntry *ie,
		struct itimerval *val)
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

static int prepare_itimers(int pid, struct task_restore_core_args *args)
{
	int fd, ret = -1;
	ItimerEntry *ie;

	fd = open_image(CR_FD_ITIMERS, O_RSTR, pid);
	if (fd < 0)
		return fd;

	ret = pb_read_one(fd, &ie, PB_ITIMERS);
	if (ret < 0)
		goto out;
	ret = itimer_restore_and_fix("real", ie, &args->itimers[0]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(fd, &ie, PB_ITIMERS);
	if (ret < 0)
		goto out;
	ret = itimer_restore_and_fix("virt", ie, &args->itimers[1]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;

	ret = pb_read_one(fd, &ie, PB_ITIMERS);
	if (ret < 0)
		goto out;
	ret = itimer_restore_and_fix("prof", ie, &args->itimers[2]);
	itimer_entry__free_unpacked(ie, NULL);
	if (ret < 0)
		goto out;
out:
	close_safe(&fd);
	return ret;
}

static inline int timespec_valid(struct timespec *ts)
{
	return (ts->tv_sec >= 0) && ((unsigned long)ts->tv_nsec < NSEC_PER_SEC);
}

static inline int posix_timer_restore_and_fix(PosixTimerEntry *pte,
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

static int open_posix_timers_image(int pid, struct restore_posix_timer **rpt,
				unsigned long *size, int *nr)
{
	int fd;
	int ret = -1;

	fd = open_image(CR_FD_POSIX_TIMERS, O_RSTR, pid);
	if (fd < 0)
		return fd;

	while (1) {
		PosixTimerEntry *pte;

		ret = pb_read_one_eof(fd, &pte, PB_POSIX_TIMERS);
		if (ret <= 0) {
			goto out;
		}

		if ((*nr + 1) * sizeof(struct restore_posix_timer) > *size) {
			unsigned long new_size = *size + PAGE_SIZE;

			if (*rpt == NULL)
				*rpt = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANON, 0, 0);
			else
				*rpt = mremap(*rpt, *size, new_size, MREMAP_MAYMOVE);
			if (*rpt == MAP_FAILED) {
				pr_perror("Can't allocate memory for posix timers");
				ret = -1;
				goto out;
			}

			*size = new_size;
		}

		ret = posix_timer_restore_and_fix(pte, *rpt + *nr);
		if (ret < 0)
			goto out;

		posix_timer_entry__free_unpacked(pte, NULL);
		(*nr)++;
	}
out:
	if (*nr > 0) {
		qsort(*rpt, *nr, sizeof(struct restore_posix_timer), cmp_posix_timer_proc_id);
	}
	close_safe(&fd);
	return ret;
}

static inline int verify_cap_size(CredsEntry *ce)
{
	return ((ce->n_cap_inh == CR_CAP_SIZE) && (ce->n_cap_eff == CR_CAP_SIZE) &&
		(ce->n_cap_prm == CR_CAP_SIZE) && (ce->n_cap_bnd == CR_CAP_SIZE));
}

static int prepare_creds(int pid, struct task_restore_core_args *args)
{
	int fd, ret;
	CredsEntry *ce;

	struct sysctl_req req[] = {
		{ "kernel/cap_last_cap", &args->cap_last_cap, CTL_U32 },
		{ },
	};

	ret = sysctl_op(req, CTL_READ);
	if (ret < 0) {
		pr_err("Failed to read max IPC message size\n");
		return -1;
	}

	fd = open_image(CR_FD_CREDS, O_RSTR, pid);
	if (fd < 0)
		return fd;

	ret = pb_read_one(fd, &ce, PB_CREDS);
	close_safe(&fd);

	if (ret < 0)
		return ret;
	if (!verify_cap_size(ce)) {
		pr_err("Caps size mismatch %d %d %d %d\n",
		       (int)ce->n_cap_inh, (int)ce->n_cap_eff,
		       (int)ce->n_cap_prm, (int)ce->n_cap_bnd);
		return -1;
	}

	args->creds = *ce;
	args->creds.cap_inh = args->cap_inh;
	memcpy(args->cap_inh, ce->cap_inh, sizeof(args->cap_inh));
	args->creds.cap_eff = args->cap_eff;
	memcpy(args->cap_eff, ce->cap_eff, sizeof(args->cap_eff));
	args->creds.cap_prm = args->cap_prm;
	memcpy(args->cap_prm, ce->cap_prm, sizeof(args->cap_prm));
	args->creds.cap_bnd = args->cap_bnd;
	memcpy(args->cap_bnd, ce->cap_bnd, sizeof(args->cap_bnd));

	/*
	 * We can set supplementary groups here. This won't affect any
	 * permission checks for us (we're still root) and will not be
	 * reset by subsequent creds changes in restorer.
	 */

	BUILD_BUG_ON(sizeof(*ce->groups) != sizeof(gid_t));
	if (setgroups(ce->n_groups, ce->groups) < 0) {
		pr_perror("Can't set supplementary groups");
		return -1;
	}

	creds_entry__free_unpacked(ce, NULL);

	/* XXX -- validate creds here? */

	return 0;
}

static VmaEntry *vma_list_remap(void *addr, unsigned long len, struct vm_area_list *vmas)
{
	VmaEntry *vma, *ret;
	struct vma_area *vma_area;

	ret = vma = mmap(addr, len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (vma != addr) {
		pr_perror("Can't remap vma area");
		return NULL;
	}

	list_for_each_entry(vma_area, &vmas->h, list) {
		*vma = vma_area->vma;
		vma++;
	}

	vma->start = 0;
	free_mappings(vmas);

	return ret;
}

static int prepare_mm(pid_t pid, struct task_restore_core_args *args)
{
	int fd, exe_fd, i, ret = -1;
	MmEntry *mm;

	fd = open_image(CR_FD_MM, O_RSTR, pid);
	if (fd < 0)
		return -1;

	if (pb_read_one(fd, &mm, PB_MM) < 0) {
		close_safe(&fd);
		return -1;
	}

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

	exe_fd = open_reg_by_id(args->mm.exe_file_id);
	if (exe_fd < 0)
		goto out;

	args->fd_exe_link = exe_fd;
	ret = 0;
out:
	mm_entry__free_unpacked(mm, NULL);
	close(fd);
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

	restorer_len = round_up(sizeof(restorer_blob), PAGE_SIZE);
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

static int prepare_rlimits(int pid, struct task_restore_core_args *ta)
{
	int fd, ret;

	ta->nr_rlim = 0;

	fd = open_image(CR_FD_RLIMIT, O_RSTR, pid);
	if (fd < 0) {
		if (errno == ENOENT) {
			pr_info("Skip rlimits for %d\n", pid);
			return 0;
		}

		return -1;
	}

	while (1) {
		int l;
		RlimitEntry *re;

		ret = pb_read_one_eof(fd, &re, PB_RLIMIT);
		if (ret <= 0)
			break;

		l = ta->nr_rlim;
		if (l == RLIM_NLIMITS) {
			pr_err("Too many rlimits in image for %d\n", pid);
			ret = -1;
			break;
		}

		ta->rlims[l].rlim_cur = decode_rlim(re->cur);
		ta->rlims[l].rlim_max = decode_rlim(re->max);
		if (ta->rlims[l].rlim_cur > ta->rlims[l].rlim_max) {
			pr_err("Can't restore cur > max for %d.%d\n", pid, l);
			ta->rlims[l].rlim_cur = ta->rlims[l].rlim_max;
		}

		rlimit_entry__free_unpacked(re, NULL);

		ta->nr_rlim++;
	}

	close(fd);
	return ret;
}

static int open_signal_image(int type, pid_t pid, siginfo_t **ptr,
					unsigned long *size, int *nr)
{
	int fd, ret, n;

	fd = open_image(type, O_RSTR, pid);
	if (fd < 0)
		return -1;

	n = 0;

	while (1) {
		SiginfoEntry *sie;
		siginfo_t *info;

		ret = pb_read_one_eof(fd, &sie, PB_SIGINFO);
		if (ret <= 0)
			break;
		if (sie->siginfo.len != sizeof(siginfo_t)) {
			pr_err("Unknown image format");
			ret = -1;
			break;
		}
		info = (siginfo_t *) sie->siginfo.data;

		if ((*nr + 1) * sizeof(siginfo_t) > *size) {
			unsigned long new_size = *size + PAGE_SIZE;

			if (*ptr == NULL)
				*ptr = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
							MAP_PRIVATE | MAP_ANON, 0, 0);
			else
				*ptr = mremap(*ptr, *size, new_size, MREMAP_MAYMOVE);
			if (*ptr == MAP_FAILED) {
				pr_perror("Can't allocate memory for siginfo-s");
				ret = -1;
				break;
			}

			*size = new_size;
		}

		memcpy(*ptr + *nr, info, sizeof(*info));
		(*nr)++;
		n++;

		siginfo_entry__free_unpacked(sie, NULL);
	}

	close(fd);

	return ret ? : n;
}

extern void __gcov_flush(void) __attribute__((weak));
void __gcov_flush(void) {}

static int sigreturn_restore(pid_t pid, CoreEntry *core)
{
	long restore_task_vma_len;
	long restore_thread_vma_len, self_vmas_len, vmas_len;

	void *mem = MAP_FAILED;
	void *restore_thread_exec_start;
	void *restore_task_exec_start;

	long new_sp, exec_mem_hint;
	long ret;
	long restore_bootstrap_len;

	struct task_restore_core_args *task_args;
	struct thread_restore_args *thread_args;
	siginfo_t *siginfo_chunk = NULL;
	int siginfo_nr = 0;
	int siginfo_shared_nr = 0;
	int *siginfo_priv_nr;
	unsigned long siginfo_size = 0;

	unsigned long vdso_rt_vma_size = 0;
	unsigned long vdso_rt_size = 0;
	unsigned long vdso_rt_delta = 0;

	struct restore_posix_timer *posix_timers_info_chunk = NULL;
	int posix_timers_nr = 0;
	unsigned long posix_timers_size = 0;

	struct vm_area_list self_vmas;
	int i;

	pr_info("Restore via sigreturn\n");

	ret = parse_smaps(pid, &self_vmas, false);
	close_proc();
	if (ret < 0)
		goto err;

	self_vmas_len = round_up((self_vmas.nr + 1) * sizeof(VmaEntry), PAGE_SIZE);
	vmas_len = round_up((rst_vmas.nr + 1) * sizeof(VmaEntry), PAGE_SIZE);

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_core_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);
	BUILD_BUG_ON(SHMEMS_SIZE % PAGE_SIZE);
	BUILD_BUG_ON(TASK_ENTRIES_SIZE % PAGE_SIZE);

	restore_task_vma_len   = round_up(sizeof(*task_args), PAGE_SIZE);
	restore_thread_vma_len = round_up(sizeof(*thread_args) * current->nr_threads, PAGE_SIZE);

	pr_info("%d threads require %ldK of memory\n",
			current->nr_threads,
			KBYTES(restore_thread_vma_len));

	siginfo_priv_nr = xmalloc(sizeof(int) * current->nr_threads);
	if (siginfo_priv_nr == NULL)
		goto err;

	ret = open_signal_image(CR_FD_SIGNAL, pid, &siginfo_chunk,
					&siginfo_size, &siginfo_nr);
	if (ret < 0) {
		if (errno != ENOENT) /* backward compatibility */
			goto err;
		ret = 0;
	}
	siginfo_shared_nr = ret;

	for (i = 0; i < current->nr_threads; i++) {
		ret = open_signal_image(CR_FD_PSIGNAL,
					current->threads[i].virt, &siginfo_chunk,
					&siginfo_size, &siginfo_nr);
		if (ret < 0) {
			if (errno != ENOENT) /* backward compatibility */
				goto err;
			ret = 0;
		}
		siginfo_priv_nr[i] = ret;
	}

	ret = open_posix_timers_image(pid, &posix_timers_info_chunk,
			&posix_timers_size, &posix_timers_nr);
	if (ret < 0) {
		if (errno != ENOENT) /* backward compatibility */
			goto err;
		ret = 0;
	}

	restore_bootstrap_len = restorer_len +
				restore_task_vma_len +
				restore_thread_vma_len +
				SHMEMS_SIZE + TASK_ENTRIES_SIZE +
				self_vmas_len + vmas_len +
				rst_tcp_socks_size +
				siginfo_size +
				posix_timers_size;

	/*
	 * Figure out how much memory runtime vdso will need.
	 */
	vdso_rt_vma_size = vdso_vma_size(&vdso_sym_rt);
	if (vdso_rt_vma_size) {
		vdso_rt_delta = ALIGN(restore_bootstrap_len, PAGE_SIZE) - restore_bootstrap_len;
		vdso_rt_size = vdso_rt_vma_size + vdso_rt_delta;
	}

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

	exec_mem_hint = restorer_get_vma_hint(pid, &rst_vmas.h, &self_vmas.h,
					      restore_bootstrap_len +
					      vdso_rt_size);
	if (exec_mem_hint == -1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n",
		       restore_bootstrap_len + vdso_rt_size);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: 0x%lx (needs ~%ldK)\n", exec_mem_hint,
			KBYTES(restore_bootstrap_len + vdso_rt_size));

	ret = remap_restorer_blob((void *)exec_mem_hint);
	if (ret < 0)
		goto err;

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	restore_thread_exec_start	= restorer_sym(exec_mem_hint, __export_restore_thread);
	restore_task_exec_start		= restorer_sym(exec_mem_hint, __export_restore_task);

	exec_mem_hint += restorer_len;

	/* VMA we need to run task_restore code */
	mem = mmap((void *)exec_mem_hint,
			restore_task_vma_len + restore_thread_vma_len,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (mem != (void *)exec_mem_hint) {
		pr_err("Can't mmap section for restore code\n");
		goto err;
	}

	memzero(mem, restore_task_vma_len + restore_thread_vma_len);
	task_args	= mem;
	thread_args	= mem + restore_task_vma_len;

	mem += restore_task_vma_len + restore_thread_vma_len;
	if (siginfo_chunk) {
		siginfo_chunk = mremap(siginfo_chunk, siginfo_size, siginfo_size,
					MREMAP_FIXED | MREMAP_MAYMOVE, mem);
		if (siginfo_chunk == MAP_FAILED) {
			pr_perror("mremap");
			goto err;
		}
	}

	task_args->siginfo_size = siginfo_size;
	task_args->siginfo_nr = siginfo_shared_nr;
	task_args->siginfo = siginfo_chunk;
	siginfo_chunk += task_args->siginfo_nr;

	mem += siginfo_size;
	if (posix_timers_info_chunk) {
		posix_timers_info_chunk = mremap(posix_timers_info_chunk,
			posix_timers_size, posix_timers_size,
			MREMAP_FIXED | MREMAP_MAYMOVE, mem);
		if (posix_timers_info_chunk == MAP_FAILED) {
			pr_perror("mremap");
			goto err;
		}
	}
	task_args->timer_n = posix_timers_nr;
	task_args->posix_timers = posix_timers_info_chunk;
	task_args->timers_sz = posix_timers_size;

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

	mem += posix_timers_size;
	ret = shmem_remap(rst_shmems, mem, SHMEMS_SIZE);
	if (ret < 0)
		goto err;
	task_args->shmems = mem;

	mem += SHMEMS_SIZE;
	ret = shmem_remap(task_entries, mem, TASK_ENTRIES_SIZE);
	if (ret < 0)
		goto err;
	task_args->task_entries = mem;

	mem += TASK_ENTRIES_SIZE;
	task_args->self_vmas = vma_list_remap(mem, self_vmas_len, &self_vmas);
	if (!task_args->self_vmas)
		goto err;

	mem += self_vmas_len;
	task_args->nr_vmas = rst_vmas.nr;
	task_args->tgt_vmas = vma_list_remap(mem, vmas_len, &rst_vmas);
	task_args->premmapped_addr = (unsigned long) current->rst->premmapped_addr;
	task_args->premmapped_len = current->rst->premmapped_len;
	if (!task_args->tgt_vmas)
		goto err;

	mem += vmas_len;
	if (rst_tcp_socks_remap(mem))
		goto err;
	task_args->rst_tcp_socks = mem;
	task_args->rst_tcp_socks_size = rst_tcp_socks_size;

	/*
	 * Arguments for task restoration.
	 */

	BUG_ON(core->mtype != CORE_ENTRY__MARCH);

	task_args->logfd	= log_get_fd();
	task_args->loglevel	= log_get_loglevel();
	task_args->sigchld_act	= sigchld_act;

	strncpy(task_args->comm, core->tc->comm, sizeof(task_args->comm));

	if (prepare_rlimits(pid, task_args))
		goto err;

	/*
	 * Fill up per-thread data.
	 */
	for (i = 0; i < current->nr_threads; i++) {
		int fd_core;
		CoreEntry *tcore;
		struct rt_sigframe *sigframe;

		thread_args[i].pid = current->threads[i].virt;
		thread_args[i].siginfo_nr = siginfo_priv_nr[i];
		thread_args[i].siginfo = siginfo_chunk;
		siginfo_chunk += thread_args[i].siginfo_nr;

		/* skip self */
		if (thread_args[i].pid == pid) {
			task_args->t = thread_args + i;
			tcore = core;
		} else {
			fd_core = open_image(CR_FD_CORE, O_RSTR, thread_args[i].pid);
			if (fd_core < 0) {
				pr_err("Can't open core data for thread %d\n",
				       thread_args[i].pid);
				goto err;
			}

			ret = pb_read_one(fd_core, &tcore, PB_CORE);
			close(fd_core);
		}

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

		if (tcore->thread_core) {
			thread_args[i].has_futex	= true;
			thread_args[i].futex_rla	= tcore->thread_core->futex_rla;
			thread_args[i].futex_rla_len	= tcore->thread_core->futex_rla_len;

			ret = prep_sched_info(&thread_args[i].sp, tcore->thread_core);
			if (ret)
				goto err;
		}

		sigframe = (struct rt_sigframe *)thread_args[i].mem_zone.rt_sigframe;

		if (construct_sigframe(sigframe, sigframe, tcore))
			goto err;

		if (thread_args[i].pid != pid)
			core_entry__free_unpacked(tcore, NULL);

		pr_info("Thread %4d stack %8p heap %8p rt_sigframe %8p\n",
				i, thread_args[i].mem_zone.stack,
				thread_args[i].mem_zone.heap,
				thread_args[i].mem_zone.rt_sigframe);

	}

	/*
	 * Restorer needs own copy of vdso parameters. Runtime
	 * vdso must be kept non intersecting with anything else,
	 * since we need it being accessible even when own
	 * self-vmas are unmaped.
	 */
	mem += (unsigned long)rst_tcp_socks_size;
	task_args->vdso_rt_parked_at = (unsigned long)mem + vdso_rt_delta;
	task_args->vdso_sym_rt = vdso_sym_rt;

	/*
	 * Adjust stack.
	 */
	new_sp = RESTORE_ALIGN_STACK((long)task_args->t->mem_zone.stack,
			sizeof(task_args->t->mem_zone.stack));

	/* No longer need it */
	core_entry__free_unpacked(core, NULL);

	ret = prepare_itimers(pid, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_creds(pid, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_mm(pid, task_args);
	if (ret < 0)
		goto err;

	mutex_init(&task_args->rst_lock);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads		= current->nr_threads;
	task_args->nr_zombies		= current->rst->nr_zombies;
	task_args->clone_restore_fn	= (void *)restore_thread_exec_start;
	task_args->thread_args		= thread_args;

	close_image_dir();

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

	/* Just to be sure */
	exit(1);
	return -1;
}
