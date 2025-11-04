#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/userfaultfd.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "cow-dump.h"
#include "uffd.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "parasite-syscall.h"
#include "mem.h"
#include "vma.h"
#include "util.h"
#include "kerndat.h"
#include "criu-log.h"

#undef LOG_PREFIX
#define LOG_PREFIX "cow-dump: "

/* COW dump state for a single process */
struct cow_dump_info {
	struct pstree_item *item;
	int uffd;				/* userfaultfd for write tracking */
	int proc_mem_fd;			/* /proc/pid/mem for reading pages */
	unsigned long total_pages;		/* Total pages being tracked */
	unsigned long dirty_pages;		/* Pages modified in current iteration */
	unsigned long iteration;		/* Current iteration number */
	struct list_head dirty_list;		/* List of dirty page ranges */
	struct page_xfer xfer;			/* Page transfer context */
};

/* Dirty page range */
struct dirty_range {
	unsigned long start;
	unsigned long len;
	struct list_head list;
};

static struct cow_dump_info *g_cow_info = NULL;

#define COW_MAX_ITERATIONS 10
#define COW_CONVERGENCE_THRESHOLD 100  /* Stop if < 100 pages dirty per iteration */

bool cow_check_kernel_support(void)
{
	unsigned long features = UFFD_FEATURE_PAGEFAULT_FLAG_WP | 
				 UFFD_FEATURE_EVENT_FORK |
				 UFFD_FEATURE_EVENT_REMAP;
	int uffd, err = 0;

	uffd = uffd_open(0, &features, &err);
	if (uffd < 0) {
		if (err == ENOSYS) {
			pr_info("userfaultfd not supported by kernel\n");
		} else if (err == EPERM) {
			pr_info("userfaultfd requires CAP_SYS_PTRACE or sysctl vm.unprivileged_userfaultfd=1\n");
		}
		return false;
	}

	if (!(features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		pr_info("userfaultfd write-protect not supported (need kernel 5.7+)\n");
		close(uffd);
		return false;
	}

	close(uffd);
	pr_info("COW dump kernel support detected\n");
	return true;
}

static int open_proc_mem(pid_t pid)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	return fd;
}

static int cow_register_vma_writeprotect(struct cow_dump_info *cdi, struct vma_area *vma)
{
	struct uffdio_register reg;
	unsigned long addr = vma->e->start;
	unsigned long len = vma->e->end - vma->e->start;
    /* Now write-protect the VMA */
	struct uffdio_writeprotect wp;
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	/* Skip non-writable or special VMAs */
	if (!(vma->e->prot & PROT_WRITE))
		return 0;
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	if (vma_entry_is(vma->e, VMA_AREA_VDSO) ||
	    vma_entry_is(vma->e, VMA_AREA_VSYSCALL) ||
	    vma_entry_is(vma->e, VMA_AREA_VVAR))
		return 0;
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	pr_debug("Registering VMA for write-protect: %lx-%lx\n", addr, addr + len);

	reg.range.start = addr;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	if (ioctl(cdi->uffd, UFFDIO_REGISTER, &reg)) {
		pr_perror("Failed to register VMA %lx-%lx", addr, addr + len);
		return -1;
	}

	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	wp.range.start = addr;
	wp.range.len = len;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	if (ioctl(cdi->uffd, UFFDIO_WRITEPROTECT, &wp)) {
		pr_perror("Failed to write-protect VMA %lx-%lx", addr, addr + len);
		return -1;
	}
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
	cdi->total_pages += len / PAGE_SIZE;
	return 0;
}

int cow_dump_init(struct pstree_item *item, struct vm_area_list *vma_area_list)
{
	struct cow_dump_info *cdi;
	struct vma_area *vma;
	unsigned long features = UFFD_FEATURE_PAGEFAULT_FLAG_WP |
				 UFFD_FEATURE_EVENT_FORK |
				 UFFD_FEATURE_EVENT_REMAP;
	int err = 0;

	pr_info("Initializing COW dump for pid %d\n", item->pid->real);

	if (!cow_check_kernel_support()) {
		pr_err("Kernel doesn't support COW dump\n");
		return -1;
	}
		pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);

	cdi = xzalloc(sizeof(*cdi));
	if (!cdi)
		return -1;

	cdi->item = item;
	INIT_LIST_HEAD(&cdi->dirty_list);
		pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);

	/* Open userfaultfd */
	cdi->uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &features, &err);
	if (cdi->uffd < 0) {
		pr_err("Failed to open userfaultfd: %d\n", err);
		goto err_free;
	}
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);

	/* Open /proc/pid/mem for reading pages */
	cdi->proc_mem_fd = open_proc_mem(item->pid->real);
	if (cdi->proc_mem_fd < 0){
		pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
		goto err_close_uffd;}
	pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);

	/* Register all writable VMAs with write-protection */
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (cow_register_vma_writeprotect(cdi, vma)) {
			pr_info("Asaf try1 file = %s, line = %d\n", __FILE__, __LINE__);
			goto err_close_mem;
		}
	}

	pr_info("COW dump initialized: tracking %lu pages\n", cdi->total_pages);
	g_cow_info = cdi;
	return 0;

err_close_mem:
	close(cdi->proc_mem_fd);
err_close_uffd:
	close(cdi->uffd);
err_free:
	xfree(cdi);
	return -1;
}

void cow_dump_fini(void)
{
	struct dirty_range *dr, *tmp;

	if (!g_cow_info)
		return;

	pr_info("Cleaning up COW dump\n");

	list_for_each_entry_safe(dr, tmp, &g_cow_info->dirty_list, list) {
		list_del(&dr->list);
		xfree(dr);
	}

	if (g_cow_info->proc_mem_fd >= 0)
		close(g_cow_info->proc_mem_fd);
	
	if (g_cow_info->uffd >= 0)
		close(g_cow_info->uffd);

	xfree(g_cow_info);
	g_cow_info = NULL;
}

static int cow_handle_write_fault(struct cow_dump_info *cdi, unsigned long addr)
{
	struct dirty_range *dr;
	unsigned long page_addr = addr & ~(PAGE_SIZE - 1);
	/* Unprotect the page so the process can continue */
	struct uffdio_writeprotect wp;
	/* Wake up the faulting thread */
	struct uffdio_range range;
    
	pr_debug("Write fault at 0x%lx\n", page_addr);
	cdi->dirty_pages++;

	/* Add to dirty list */
	dr = xmalloc(sizeof(*dr));
	if (!dr)
		return -1;

	dr->start = page_addr;
	dr->len = PAGE_SIZE;
	INIT_LIST_HEAD(&dr->list);
	list_add_tail(&dr->list, &cdi->dirty_list);


	wp.range.start = page_addr;
	wp.range.len = PAGE_SIZE;
	wp.mode = 0; /* Clear write-protect */

	if (ioctl(cdi->uffd, UFFDIO_WRITEPROTECT, &wp)) {
		pr_perror("Failed to unprotect page at 0x%lx", page_addr);
		return -1;
	}


	range.start = page_addr;
	range.len = PAGE_SIZE;
	
	if (ioctl(cdi->uffd, UFFDIO_WAKE, &range)) {
		pr_perror("Failed to wake thread after unprotect");
		return -1;
	}

	return 0;
}

static int cow_process_events(struct cow_dump_info *cdi, bool blocking)
{
	struct uffd_msg msg;
	int ret;
	//int flags = blocking ? MSG_WAITALL : MSG_DONTWAIT;

	while (1) {
		ret = read(cdi->uffd, &msg, sizeof(msg));
		if (ret < 0) {
			if (errno == EAGAIN && !blocking)
				return 0; /* No more events */
			pr_perror("Failed to read uffd event");
			return -1;
		}

		if (ret != sizeof(msg)) {
			pr_err("Short read from uffd: %d\n", ret);
			return -1;
		}

		switch (msg.event) {
		case UFFD_EVENT_PAGEFAULT:
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
				/* Write fault - track it */
				if (cow_handle_write_fault(cdi, msg.arg.pagefault.address))
					return -1;
			}
			break;

		case UFFD_EVENT_FORK:
			pr_warn("Process forked during COW dump (not fully supported)\n");
			break;

		case UFFD_EVENT_REMAP:
			pr_debug("Memory remap event\n");
			break;

		default:
			pr_err("Unexpected uffd event: %u\n", msg.event);
			return -1;
		}
	}

	return 0;
}

static int cow_send_dirty_pages(struct cow_dump_info *cdi)
{
	struct dirty_range *dr, *tmp;
	void *buf;
	int ret = 0;

	if (list_empty(&cdi->dirty_list))
		return 0;

	buf = xmalloc(PAGE_SIZE);
	if (!buf)
		return -1;

	pr_info("Iteration %lu: Sending %lu dirty pages\n", 
		cdi->iteration, cdi->dirty_pages);

	list_for_each_entry_safe(dr, tmp, &cdi->dirty_list, list) {
		ssize_t bytes;

		/* Read page from process memory */
		bytes = pread(cdi->proc_mem_fd, buf, PAGE_SIZE, dr->start);
		if (bytes != PAGE_SIZE) {
			pr_perror("Failed to read page at 0x%lx", dr->start);
			ret = -1;
			break;
		}

		/* TODO: Send page to destination via page server */
		/* For now, we just track it */
		
		pr_debug("Captured dirty page at 0x%lx\n", dr->start);

		/* Remove from list */
		list_del(&dr->list);
		xfree(dr);
	}

	xfree(buf);
	return ret;
}

int cr_cow_mem_dump(void)
{
	struct cow_dump_info *cdi = g_cow_info;
	int ret = -1;
	bool converged = false;

	if (!cdi) {
		pr_err("COW dump not initialized\n");
		return -1;
	}

	pr_info("Starting COW memory dump\n");
	pr_info("Tracking %lu pages across all VMAs\n", cdi->total_pages);

	/* Iterative tracking loop */
	for (cdi->iteration = 1; cdi->iteration <= COW_MAX_ITERATIONS; cdi->iteration++) {
		cdi->dirty_pages = 0;

		pr_info("COW iteration %lu: processing write faults...\n", cdi->iteration);

		/* Process write faults for a time window */
		/* In production, this would be more sophisticated with epoll */
		sleep(1); /* Give process time to run */

		/* Collect any pending write faults */
		if (cow_process_events(cdi, false))
			goto out;

		/* Send dirty pages to destination */
		if (cow_send_dirty_pages(cdi))
			goto out;

		/* Check for convergence */
		if (cdi->dirty_pages < COW_CONVERGENCE_THRESHOLD) {
			pr_info("Converged: only %lu dirty pages\n", cdi->dirty_pages);
			converged = true;
			break;
		}

		pr_info("Iteration %lu: %lu dirty pages (not converged yet)\n",
			cdi->iteration, cdi->dirty_pages);
	}

	if (!converged) {
		pr_warn("Did not converge after %d iterations\n", COW_MAX_ITERATIONS);
	}

	pr_info("COW memory dump completed successfully\n");
	ret = 0;

out:
	return ret;
}
