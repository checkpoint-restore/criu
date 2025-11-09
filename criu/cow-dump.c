#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/userfaultfd.h>
#include <pthread.h>

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
#include "parasite.h"

#undef LOG_PREFIX
#define LOG_PREFIX "cow-dump: "

/* COW dump state for a single process */
struct cow_dump_info {
	struct pstree_item *item;
	int uffd;				/* userfaultfd for write tracking */
	int proc_mem_fd;			/* /proc/pid/mem for reading pages */
	unsigned long total_pages;		/* Total pages being tracked */
	unsigned long dirty_pages;		/* Pages modified in current iteration */
	unsigned long dirty_pages_dumped;	/* Pages already written to disk */
	unsigned long iteration;		/* Current iteration number */
	struct list_head dirty_list;		/* List of dirty page ranges */	
};

/* Dirty page range */
struct dirty_range {
	unsigned long start;
	unsigned long len;
	struct list_head list;
};

static struct cow_dump_info *g_cow_info = NULL;
static pthread_t g_monitor_thread;
static volatile bool g_stop_monitoring = false;

#define COW_MAX_ITERATIONS 10
#define COW_CONVERGENCE_THRESHOLD 100  /* Stop if < 100 pages dirty per iteration */
#define COW_FLUSH_THRESHOLD 1000       /* Flush to disk every 1000 pages */

bool cow_check_kernel_support(void)
{
	unsigned long features = UFFD_FEATURE_WP_ASYNC |
				 UFFD_FEATURE_PAGEFAULT_FLAG_WP | 
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

	if (!(features & UFFD_FEATURE_WP_ASYNC)) {
		pr_info("userfaultfd write-protect feature not supported (need kernel 5.7+)\n");
		close(uffd);
		return false;
	}

	if (!(features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		pr_info("userfaultfd WP pagefault flag not supported (need kernel 5.7+)\n");
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

int cow_dump_init(struct pstree_item *item, struct vm_area_list *vma_area_list, struct parasite_ctl *ctl)
{
	struct cow_dump_info *cdi;
	struct vma_area *vma;
	struct parasite_cow_dump_args *args;
	struct parasite_vma_entry *p_vma;

	int ret;
	unsigned long args_size;
	unsigned int nr_vmas = 0;

	pr_info("Initializing COW dump for pid %d (via parasite)\n", item->pid->real);

	if (!cow_check_kernel_support()) {
		pr_err("Kernel doesn't support COW dump\n");
		return -1;
	}

	cdi = xzalloc(sizeof(*cdi));
	if (!cdi)
		return -1;

	cdi->item = item;
	INIT_LIST_HEAD(&cdi->dirty_list);
	cdi->uffd = -1; /* Will be received from parasite */

	/* Open /proc/pid/mem for reading pages */
	cdi->proc_mem_fd = open_proc_mem(item->pid->real);
	if (cdi->proc_mem_fd < 0)
		goto err_free;

	/* Prepare parasite arguments - count writable VMAs */
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		if (vma->e->prot & PROT_WRITE)
			nr_vmas++;
	}

	/* Allocate parasite args - includes space for VMAs and failed indices */
	args_size = sizeof(*args) + 
		    nr_vmas * sizeof(struct parasite_vma_entry) +
		    nr_vmas * sizeof(unsigned int);  /* Space for failed indices */
	args = compel_parasite_args_s(ctl, args_size);
	if (!args) {
		pr_err("Failed to allocate parasite args\n");
		goto err_close_mem;
	}

	args->nr_vmas = nr_vmas;
	args->total_pages = 0;
	args->nr_failed_vmas = 0;
	args->ret = -1;

	/* Fill VMA entries */
	p_vma = cow_dump_vmas(args);
	nr_vmas = 0;
	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;
		if (!(vma->e->prot & PROT_WRITE))
			continue;

		p_vma[nr_vmas].start = vma->e->start;
		p_vma[nr_vmas].len = vma->e->end - vma->e->start;
		p_vma[nr_vmas].prot = vma->e->prot;
		nr_vmas++;
	}

	pr_info("Calling parasite to register %u VMAs\n", args->nr_vmas);

	/* Call parasite to create uffd and perform registration (async) */
	ret = compel_rpc_call(PARASITE_CMD_COW_DUMP_INIT, ctl);
	if (ret < 0) {
		pr_err("Failed to initiate COW dump RPC\n");
		goto err_close_mem;
	}

	/* Receive userfaultfd from parasite */
	compel_util_recv_fd(ctl, &cdi->uffd);
	if (cdi->uffd < 0) {
		pr_err("Failed to receive userfaultfd from parasite: %d\n", cdi->uffd);
		goto err_close_mem;
	}
	pr_info("Got fd %d VMAs\n", cdi->uffd);
	/* Wait for parasite to complete */
	ret = compel_rpc_sync(PARASITE_CMD_COW_DUMP_INIT, ctl);
	if (ret < 0 || args->ret != 0) {
		pr_err("Parasite COW dump init failed: %d (ret=%d)\n", ret, args->ret);
		close(cdi->uffd);
		cdi->uffd = -1;
		goto err_close_mem;
	}

	cdi->total_pages = args->total_pages;
	cdi->dirty_pages_dumped = 0;
		
	pr_info("COW dump initialized: tracking %lu pages, uffd=%d\n", 
		cdi->total_pages, cdi->uffd);
	
	
	g_cow_info = cdi;
	return 0;

err_close_mem:
	close(cdi->proc_mem_fd);
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

	if (g_cow_info->pp)
		destroy_page_pipe(g_cow_info->pp);

	
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
	void* page;
	struct uffdio_writeprotect wp;
	struct uffdio_range range;
	
    
	pr_debug("Write fault at 0x%lx\n", page_addr);

	cdi->dirty_pages++;

	/* Add to dirty list for tracking */
	dr = xmalloc(sizeof(*dr));
	if (!dr) {
		return -1;
	}

	page = xmalloc(PAGE_SIZE);
	//memcpy(page,(void*)page_addr, PAGE_SIZE);

	dr->start = (unsigned long)page;
	dr->len = PAGE_SIZE;
	INIT_LIST_HEAD(&dr->list);
	list_add_tail(&dr->list, &cdi->dirty_list);
	

	/* Unprotect the page so the process can continue */
	wp.range.start = page_addr;
	wp.range.len = PAGE_SIZE;
	wp.mode = 0; /* Clear write-protect */

	if (ioctl(cdi->uffd, UFFDIO_WRITEPROTECT, &wp)) {
		pr_perror("Failed to unprotect page at 0x%lx", page_addr);
		return -1;
	}

	/* Wake up the faulting thread */
	range.start = page_addr;
	range.len = PAGE_SIZE;
	
	if (ioctl(cdi->uffd, UFFDIO_WAKE, &range)) {
		pr_perror("Failed to wake thread after unprotect");
		return -1;
	}
	
	cdi->total_pages--;
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
			pr_info("Memory remap event\n");
			break;

		default:
			pr_err("Unexpected uffd event: %u\n", msg.event);
			return -1;
		}
	}

	return 0;
}

/* Background thread that monitors for write faults */
static void *cow_monitor_thread(void *arg)
{	
	int iteration_count = 0;
	struct cow_dump_info *cdi = (struct cow_dump_info *)arg;
	
	pr_info("COW monitor thread started\n");
	
	while (g_cow_info->total_pages != 0) {
			

		/* Process events with short timeout */
		if (cow_process_events(cdi, false) < 0) {
			pr_err("Error processing COW events in monitor thread\n");
			break;
		}
		/* Small delay to avoid busy-waiting */
		//usleep(1000); /* 1ms */
		/* Print total pages once per second */
		iteration_count++;
		if (iteration_count >= 10000) { /* 1000 * 1ms = 1 second */
			pr_info("COW monitor: %lu pages remaining\n", g_cow_info->total_pages);
			iteration_count = 0;
		}

	}
	
	pr_info("COW monitor thread stopped\n");
	return NULL;
}

int cow_start_monitor_thread(void)
{
	int ret;
	
	if (!g_cow_info) {
		pr_err("COW dump not initialized\n");
		return -1;
	}
	
	g_stop_monitoring = false;
	
	ret = pthread_create(&g_monitor_thread, NULL, cow_monitor_thread, g_cow_info);
	if (ret) {
		pr_perror("Failed to create COW monitor thread");
		return -1;
	}
	
	pr_info("COW monitor thread created successfully\n");
	return 0;
}

int cow_stop_monitor_thread(void)
{
	void *retval;
	
	if (!g_cow_info) {
		return 0; /* Nothing to stop */
	}
	
	pr_info("Stopping COW monitor thread\n");
	g_stop_monitoring = true;
	
	/* Wait for thread to finish */
	if (pthread_join(g_monitor_thread, &retval)) {
		pr_perror("Failed to join COW monitor thread");
		return -1;
	}
	
	pr_info("COW monitor thread stopped successfully\n");
	return 0;
}
