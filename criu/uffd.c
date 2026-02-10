#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "linux/userfaultfd.h"

#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "criu-plugin.h"
#include "pagemap.h"
#include "files-reg.h"
#include "kerndat.h"
#include "mem.h"
#include "uffd.h"
#include "util-pie.h"
#include "protobuf.h"
#include "pstree.h"
#include "crtools.h"
#include "cr_options.h"
#include "xmalloc.h"
#include <compel/plugins/std/syscall-codes.h>
#include "restorer.h"
#include "page-xfer.h"
#include "common/lock.h"
#include "rst-malloc.h"
#include "tls.h"
#include "fdstore.h"
#include "util.h"
#include "namespaces.h"
#include "pagemap.h"
#undef LOG_PREFIX
#define LOG_PREFIX "uffd: "

#define lp_debug(lpi, fmt, arg...)  pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...)   pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...)   pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...)    pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

#define NEED_UFFD_API_FEATURES \
	(UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_EVENT_REMOVE)

#define LAZY_PAGES_SOCK_NAME "lazy-pages.socket"

#define LAZY_PAGES_RESTORE_FINISHED 0x52535446 /* ReSTore Finished */

/*
 * Background transfer parameters.
 * The default xfer length is arbitrary set to 64Kbytes
 * The limit of 4Mbytes matches the maximal chunk size we can have in
 * a pipe in the page-server
 */
#define DEFAULT_XFER_LEN (64 << 10)
#define MAX_XFER_LEN	 (4 << 20)

static mutex_t *lazy_sock_mutex;

struct lazy_iov {
	struct list_head l;
	unsigned long start;	 /* run-time start address, tracks remaps */
	unsigned long end;	 /* run-time end address, tracks remaps */
	unsigned long img_start; /* start address at the dump time */
};

struct lazy_pages_info {
	int pid;
	bool exited;

	struct list_head iovs;
	struct list_head reqs;

	struct lazy_pages_info *parent;
	unsigned ref_cnt;

	struct page_read pr;

	unsigned long xfer_len; /* in pages */
	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	unsigned long buf_size;
	void *buf;
};

/* global lazy-pages daemon state */
static LIST_HEAD(lpis);
static LIST_HEAD(exiting_lpis);
static LIST_HEAD(pending_lpis);
static int epollfd;
static bool restore_finished;
static struct epoll_rfd lazy_sk_rfd;
/* socket for communication with lazy-pages daemon */
static int lazy_pages_sk_id = -1;

/* Pending EAGAIN requests (for bulk mode) */
struct uffd_eagain_request {
	struct list_head l;
	struct lazy_pages_info *lpi;
	__u64 address;
	unsigned long nr_pages;
	void *buf;  /* Copy of data that couldn't be written */
};
static LIST_HEAD(eagain_requests);

/* Histogram statistics structure */
static struct {
	/* Histogram buckets by page count: 1, 16, 32, 64, 128, 256, 512, 1024, >1024 */
	unsigned long pf_hist[9]; /* Page fault histogram */
	unsigned long bg_hist[9]; /* Background transfer histogram */

	unsigned long total_pf_reqs;
	unsigned long total_bg_reqs;
	unsigned long total_pages;

	/* Timing statistics (nanoseconds) */
	unsigned long io_complete_bulk_total_ns;
	unsigned long io_complete_bulk_count;
	unsigned long io_complete_bulk_count_start;
	unsigned long uffd_copy_total_ns;
	unsigned long uffd_copy_count;
	unsigned long drop_iovs_total_ns;
	unsigned long drop_iovs_count;

	/* EAGAIN retry statistics */
	unsigned long eagain_processed;
	unsigned long eagain_succeeded;
	unsigned long eagain_blocked;
	unsigned long eagain_errors;
	unsigned long eagain_skipped;
	unsigned long eagain_total_ns;
	unsigned long eagain_calls;

	time_t last_print_time;
} uffd_stats;

static int get_histogram_bucket(unsigned long nr_pages)
{
	if (nr_pages == 1)
		return 0; /* 4KB */
	if (nr_pages <= 16)
		return 1; /* 64KB */
	if (nr_pages <= 32)
		return 2; /* 128KB */
	if (nr_pages <= 64)
		return 3; /* 256KB */
	if (nr_pages <= 128)
		return 4; /* 512KB */
	if (nr_pages <= 256)
		return 5; /* 1MB */
	if (nr_pages <= 512)
		return 6; /* 2MB */
	if (nr_pages <= 1024)
		return 7; /* 4MB */
	return 8;	  /* >4MB */
}

static const char *get_bucket_label(int bucket)
{
	switch (bucket) {
	case 0:
		return "4K";
	case 1:
		return "64K";
	case 2:
		return "128K";
	case 3:
		return "256K";
	case 4:
		return "512K";
	case 5:
		return "1M";
	case 6:
		return "2M";
	case 7:
		return "4M";
	case 8:
		return ">4M";
	default:
		return "?";
	}
}

void check_and_print_uffd_stats(void)
{
	time_t now = time(NULL);
	int i;	

	if (now - uffd_stats.last_print_time >= 1) {
		
		{
			struct timespec ts;
			struct tm *tm;
			clock_gettime(CLOCK_REALTIME, &ts);
			tm = localtime(&ts.tv_sec);
			pr_debug("[UFFD_STATS] [%02d:%02d:%02d.%03ld] reqs=%lu(pf:%lu,bg:%lu) pages=%lu\n",
				tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000000,
				uffd_stats.total_pf_reqs + uffd_stats.total_bg_reqs,
				uffd_stats.total_pf_reqs,
				uffd_stats.total_bg_reqs,
				uffd_stats.total_pages);
		}

		/* Print page fault histogram */

		pr_debug("  PF: ");
		for (i = 0; i < 9; i++) {
			if (uffd_stats.pf_hist[i] > 0)
				pr_debug(" %s=%lu", get_bucket_label(i), uffd_stats.pf_hist[i]);
		}
		pr_debug("\n");

		/* Print background transfer histogram */

		pr_debug("  BG: ");
		for (i = 0; i < 9; i++) {
			if (uffd_stats.bg_hist[i] > 0)
				pr_debug(" %s=%lu", get_bucket_label(i), uffd_stats.bg_hist[i]);
		}
		pr_debug("\n");

		/* Print timing stats */
		if (uffd_stats.io_complete_bulk_count_start > 0) {
			pr_debug("  TIMING: io_bulk=%lu ns (%lu, %lu ops) copy=%lu ns (%lu ops) drop=%lu ns (%lu ops)\n",
				uffd_stats.io_complete_bulk_total_ns / uffd_stats.io_complete_bulk_count,
				uffd_stats.io_complete_bulk_count,
				uffd_stats.io_complete_bulk_count_start,
				uffd_stats.uffd_copy_count > 0 ? uffd_stats.uffd_copy_total_ns / uffd_stats.uffd_copy_count : 0,
				uffd_stats.uffd_copy_count,
				uffd_stats.drop_iovs_count > 0 ? uffd_stats.drop_iovs_total_ns / uffd_stats.drop_iovs_count : 0,
				uffd_stats.drop_iovs_count);
		}

		/* Print EAGAIN stats */
		if (uffd_stats.eagain_processed > 0 || uffd_stats.eagain_skipped > 0 || uffd_stats.eagain_calls > 0) {
			pr_debug("  EAGAIN: processed=%lu succeeded=%lu blocked=%lu errors=%lu skipped=%lu | time=%lu ns (%lu calls)\n",
				uffd_stats.eagain_processed,
				uffd_stats.eagain_succeeded,
				uffd_stats.eagain_blocked,
				uffd_stats.eagain_errors,
				uffd_stats.eagain_skipped,
				uffd_stats.eagain_calls > 0 ? uffd_stats.eagain_total_ns / uffd_stats.eagain_calls : 0,
				uffd_stats.eagain_calls);
		}

		/* Reset all counters */
		memset(&uffd_stats, 0, sizeof(uffd_stats));
		uffd_stats.last_print_time = now;
	}
}

static int handle_uffd_event(struct epoll_rfd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_LIST_HEAD(&lpi->reqs);
	INIT_LIST_HEAD(&lpi->l);
	lpi->lpfd.read_event = handle_uffd_event;
	lpi->xfer_len = DEFAULT_XFER_LEN;
	lpi->ref_cnt = 1;

	return lpi;
}

static void free_iovs(struct lazy_pages_info *lpi)
{
	struct lazy_iov *p, *n;
	lp_err(lpi, "=== free_iovs ===\n");

	list_for_each_entry_safe(p, n, &lpi->iovs, l) {
		list_del(&p->l);
		xfree(p);
	}

	list_for_each_entry_safe(p, n, &lpi->reqs, l) {
		list_del(&p->l);
		xfree(p);
	}
}

static void lpi_fini(struct lazy_pages_info *lpi);

static inline void lpi_put(struct lazy_pages_info *lpi)
{
	lpi->ref_cnt--;
	if (!lpi->ref_cnt)
		lpi_fini(lpi);
}

static inline void lpi_get(struct lazy_pages_info *lpi)
{
	lpi->ref_cnt++;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	if (!lpi)
		return;
	xfree(lpi->buf);
	free_iovs(lpi);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->parent)
		lpi_put(lpi->parent);
	if (!lpi->parent && lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	xfree(lpi);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	int len;

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path), "%s", LAZY_PAGES_SOCK_NAME);
	if (len >= sizeof(saddr->sun_path)) {
		pr_err("Wrong UNIX socket name: %s\n", LAZY_PAGES_SOCK_NAME);
		return -1;
	}

	return 0;
}

static int send_uffd(int sendfd, int pid)
{
	int fd;
	int ret = -1;

	if (sendfd < 0)
		return -1;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("%s: get_service_fd\n", __func__);
		return -1;
	}

	mutex_lock(lazy_sock_mutex);

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	pr_debug("Sending PID %d\n", pid);
	if (send(fd, &pid, sizeof(pid), 0) < 0) {
		pr_perror("PID sending error");
		goto out;
	}

	/* for a zombie process pid will be negative */
	if (pid < 0) {
		ret = 0;
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_err("send_fd error\n");
		goto out;
	}

	ret = 0;
out:
	mutex_unlock(lazy_sock_mutex);
	close(fd);
	return ret;
}

int lazy_pages_setup_zombie(int pid)
{
	if (!opts.lazy_pages)
		return 0;

	if (send_uffd(0, -pid))
		return -1;

	return 0;
}

bool uffd_noncooperative(void)
{
	unsigned long features = NEED_UFFD_API_FEATURES;

	return (kdat.uffd_features & features) == features;
}

static int uffd_api_ioctl(void *arg, int fd, pid_t pid)
{
	struct uffdio_api *uffdio_api = arg;

	return ioctl(fd, UFFDIO_API, uffdio_api);
}

int uffd_open(int flags, unsigned long *features, int *err)
{
	struct uffdio_api uffdio_api = { 0 };
	int uffd;

	uffd = syscall(SYS_userfaultfd, flags);
	if (uffd == -1) {
		pr_info("Lazy pages are not available: %s\n", strerror(errno));
		if (err)
			*err = errno;
		return -1;
	}

	uffdio_api.api = UFFD_API;
	if (features)
		uffdio_api.features = *features;

	if (userns_call(uffd_api_ioctl, 0, &uffdio_api, sizeof(uffdio_api), uffd)) {
		pr_perror("Failed to get uffd API");
		goto close;
	}

	if (uffdio_api.api != UFFD_API) {
		pr_err("Incompatible uffd API: expected %llu, got %llu\n", UFFD_API, uffdio_api.api);
		goto close;
	}

	if (features)
		*features = uffdio_api.features;

	return uffd;

close:
	close(uffd);
	return -1;
}

/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(int pid, struct task_restore_args *task_args)
{
	unsigned long features = kdat.uffd_features & NEED_UFFD_API_FEATURES;

	if (!opts.lazy_pages) {
		task_args->uffd = -1;
		return 0;
	}

	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &features, NULL);
	if (task_args->uffd < 0) {
		pr_perror("Unable to open an userfaultfd descriptor");
		return -1;
	}

	if (send_uffd(task_args->uffd, pid) < 0)
		goto err;

	return 0;
err:
	close(task_args->uffd);
	return -1;
}

int prepare_lazy_pages_socket(void)
{
	int fd, len, ret = -1;
	struct sockaddr_un sun;

	if (!opts.lazy_pages)
		return 0;

	if (prepare_sock_addr(&sun))
		return -1;

	lazy_sock_mutex = shmalloc(sizeof(*lazy_sock_mutex));
	if (!lazy_sock_mutex)
		return -1;

	mutex_init(lazy_sock_mutex);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (connect(fd, (struct sockaddr *)&sun, len) < 0) {
		pr_perror("connect to %s failed", sun.sun_path);
		goto out;
	}

	lazy_pages_sk_id = fdstore_add(fd);
	if (lazy_pages_sk_id < 0) {
		pr_perror("Can't add fd to fdstore");
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(saddr->sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(saddr->sun_path);

	if (bind(fd, (struct sockaddr *)saddr, len) < 0) {
		goto out;
	}

	if (listen(fd, 10) < 0) {
		goto out;
	}

	return fd;

out:
	close(fd);
	return -1;
}

static MmEntry *init_mm_entry(struct lazy_pages_info *lpi)
{
	struct cr_img *img;
	MmEntry *mm;
	int ret;

	img = open_image(CR_FD_MM, O_RSTR, lpi->pid);
	if (!img)
		return NULL;

	ret = pb_read_one_eof(img, &mm, PB_MM);
	close_image(img);
	if (ret == -1)
		return NULL;
	lp_debug(lpi, "Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static struct lazy_iov *find_iov(struct lazy_pages_info *lpi, unsigned long addr)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &lpi->iovs, l)
		if (addr >= iov->start && addr < iov->end)
			return iov;

	return NULL;
}

static int split_iov(struct lazy_iov *iov, unsigned long addr)
{
	struct lazy_iov *new;

	new = xzalloc(sizeof(*new));
	if (!new)
		return -1;

	new->start = addr;
	new->img_start = iov->img_start + addr - iov->start;
	new->end = iov->end;
	iov->end = addr;
	list_add(&new->l, &iov->l);

	return 0;
}

static void iov_list_insert(struct lazy_iov *new, struct list_head *dst)
{
	struct lazy_iov *iov;

	if (list_empty(dst)) {
		list_move(&new->l, dst);
		return;
	}

	list_for_each_entry(iov, dst, l) {
		if (new->start < iov->start) {
			list_move_tail(&new->l, &iov->l);
			break;
		}
		if (list_is_last(&iov->l, dst) && new->start > iov->start) {
			list_move(&new->l, &iov->l);
			break;
		}
	}
}

static void merge_iov_lists(struct list_head *src, struct list_head *dst)
{
	struct lazy_iov *iov, *n;

	if (list_empty(src))
		return;

	list_for_each_entry_safe(iov, n, src, l)
		iov_list_insert(iov, dst);
}

static int __copy_iov_list(struct list_head *src, struct list_head *dst)
{
	struct lazy_iov *iov, *new;

	list_for_each_entry(iov, src, l) {
		new = xzalloc(sizeof(*new));
		if (!new)
			return -1;

		new->start = iov->start;
		new->img_start = iov->img_start;
		new->end = iov->end;

		list_add_tail(&new->l, dst);
	}

	return 0;
}

static int copy_iovs(struct lazy_pages_info *src, struct lazy_pages_info *dst)
{
	if (__copy_iov_list(&src->iovs, &dst->iovs))
		goto free_iovs;

	if (__copy_iov_list(&src->reqs, &dst->reqs))
		goto free_iovs;

	/*
	 * The IOVs already in flight for the parent process need to be
	 * transferred again for the child process
	 */
	merge_iov_lists(&dst->reqs, &dst->iovs);

	dst->buf_size = src->buf_size;
	if (posix_memalign(&dst->buf, PAGE_SIZE, dst->buf_size))
		goto free_iovs;

	return 0;

free_iovs:
	free_iovs(dst);
	return -1;
}

/*
 * Purge range (addr, addr + len) from lazy_iovs. The range may
 * cover several continuous IOVs.
 */
static int __drop_iovs(struct list_head *iovs, unsigned long addr, unsigned long len)
{
	struct lazy_iov *iov, *n;
	unsigned long drop_end;

	if (!len)
		return 0;

	drop_end = addr + len;
	if (drop_end < addr)
		drop_end = ULONG_MAX;

	list_for_each_entry_safe(iov, n, iovs, l) {
		unsigned long start = iov->start;
		unsigned long end = iov->end;
		unsigned long overlap_start;
		unsigned long overlap_end;

		if (end <= addr)
			continue;

		if (start >= drop_end)
			break;

		overlap_start = max(start, addr);
		overlap_end = min(end, drop_end);
		if (overlap_start >= overlap_end)
			continue;

		if (overlap_start == start && overlap_end == end) {
			list_del(&iov->l);
			xfree(iov);
			continue;
		}

		if (overlap_start == start) {
			iov->start = overlap_end;
			iov->img_start += overlap_end - start;
			continue;
		}

		if (overlap_end == end) {
			iov->end = overlap_start;
			continue;
		}

		if (split_iov(iov, overlap_end))
			return -1;
		iov->end = overlap_start;
		break;
	}

	return 0;
}

static int drop_iovs(struct lazy_pages_info *lpi, unsigned long addr, unsigned long len)
{
	if (__drop_iovs(&lpi->iovs, addr, len))
		return -1;

	if (__drop_iovs(&lpi->reqs, addr, len))
		return -1;

	return 0;
}

static struct lazy_iov *extract_range(struct lazy_iov *iov, unsigned long start, unsigned long end)
{
	/* move the IOV tail into a new IOV */
	if (end < iov->end)
		if (split_iov(iov, end))
			return NULL;

	if (start == iov->start)
		return iov;

	/* after splitting the IOV head we'll need the ->next IOV */
	if (split_iov(iov, start))
		return NULL;

	return list_entry(iov->l.next, struct lazy_iov, l);
}

static int __remap_iovs(struct list_head *iovs, unsigned long from, unsigned long to, unsigned long len)
{
	LIST_HEAD(remaps);

	unsigned long off = to - from;
	struct lazy_iov *iov, *n;

	pr_err("__remap_iovs: from=0x%lx to=0x%lx len=0x%lx (off=0x%lx)\n", from, to, len, off);

	list_for_each_entry_safe(iov, n, iovs, l) {
		if (from >= iov->end) {
			pr_debug("    Skipping: from >= iov->end\n");
			continue;
		}

		if (len <= 0 || from + len <= iov->start) {
			pr_debug("    Breaking: len exhausted or past iov\n");
			break;
		}

		if (from < iov->start) {
			pr_debug("    Adjusting: from < iov->start, moving from to 0x%lx\n", iov->start);
			len -= (iov->start - from);
			from = iov->start;
		}

		if (from > iov->start) {
			pr_debug("    Splitting IOV at from=0x%lx\n", from);
			if (split_iov(iov, from))
				return -1;
			list_safe_reset_next(iov, n, l);
			continue;
		}

		if (from + len < iov->end) {
			pr_debug("    Splitting IOV at from+len=0x%lx\n", from + len);
			if (split_iov(iov, from + len))
				return -1;
			list_safe_reset_next(iov, n, l);
		}

		/* here we have iov->start = from, iov->end <= from + len */
		pr_debug("    Remapping IOV: 0x%lx-0x%lx -> 0x%lx-0x%lx\n",
			 iov->start, iov->end, iov->start + off, iov->end + off);
		from = iov->end;
		len -= iov->end - iov->start;
		iov->start += off;
		iov->end += off;
		list_move_tail(&iov->l, &remaps);
	}

	merge_iov_lists(&remaps, iovs);
	pr_debug("__remap_iovs: complete\n");

	return 0;
}

static int remap_iovs(struct lazy_pages_info *lpi, unsigned long from, unsigned long to, unsigned long len)
{
	if (__remap_iovs(&lpi->iovs, from, to, len))
		return -1;

	if (__remap_iovs(&lpi->reqs, from, to, len))
		return -1;

	return 0;
}

/*
 * Create a list of IOVs that can be handled using userfaultfd. The
 * IOVs generally correspond to lazy pagemap entries, except the cases
 * when a single pagemap entry covers several VMAs. In those cases
 * IOVs are split at VMA boundaries because UFFDIO_COPY may be done
 * only inside a single VMA.
 * We assume here that pagemaps and VMAs are sorted.
 */
static int collect_iovs(struct lazy_pages_info *lpi)
{
	unsigned long start, end, len, nr_pages = 0;
	int n_vma = 0, max_iov_len = 0, ret = -1;
	struct page_read *pr = &lpi->pr;
	struct lazy_iov *iov;
	MmEntry *mm;
	unsigned long total_pagemap_entries = 0;
	unsigned long lazy_pagemap_entries = 0;

	mm = init_mm_entry(lpi);
	if (!mm)
		return -1;

	lp_err(lpi, "Starting IOV collection for %zd VMAs\n", mm->n_vmas);

	while (pr->advance(pr)) {
		total_pagemap_entries++;

		if (!pagemap_lazy(pr->pe)) {
			lp_err(lpi, "Skipping non-lazy pagemap entry at 0x%llx (%lu pages)\n",
			       (unsigned long long)pr->pe->vaddr, (unsigned long)pr->pe->nr_pages);
			continue;
		}

		lazy_pagemap_entries++;
		start = pr->pe->vaddr;
		end = start + pr->pe->nr_pages * page_size();
		nr_pages += pr->pe->nr_pages;

		lp_warn(lpi, "Processing lazy pagemap entry: 0x%llx-0x%llx (%lu pages)\n",
			(unsigned long long)start, (unsigned long long)end,
			(unsigned long)pr->pe->nr_pages);

		while (n_vma < mm->n_vmas) {
			VmaEntry *vma = mm->vmas[n_vma];

			if (start >= vma->end) {
				lp_err(lpi, "  Skipping VMA %d: 0x%llx-0x%llx (start >= vma->end)\n",
				       n_vma, (unsigned long long)vma->start, (unsigned long long)vma->end);
				n_vma++;
				continue;
			}

			iov = xzalloc(sizeof(*iov));
			if (!iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			iov->start = start;
			iov->img_start = start;
			iov->end = iov->start + len;
			list_add_tail(&iov->l, &lpi->iovs);

			lp_warn(lpi, "  Created IOV for VMA %d: 0x%lx-0x%lx (len=%lu, %lu pages)\n",
				n_vma, iov->start, iov->end, len, len / PAGE_SIZE);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->end)
				break;

			start = vma->end;
			n_vma++;
		}
	}

	lp_warn(lpi, "IOV collection complete: %lu total pagemap entries, %lu lazy entries, %lu pages in IOVs\n",
		total_pagemap_entries, lazy_pagemap_entries, nr_pages);

	/* Dump all collected IOVs for debugging */
	{
		struct lazy_iov *iov;
		unsigned long iov_count = 0;

		lp_err(lpi, "=== IOV DUMP START ===\n");
		list_for_each_entry(iov, &lpi->iovs, l) {
			lp_err(lpi, "IOV[%lu]: start=0x%lx end=0x%lx img_start=0x%lx len=%lu pages=%lu\n",
			       iov_count, iov->start, iov->end, iov->img_start,
			       iov->end - iov->start, (iov->end - iov->start) / PAGE_SIZE);
			iov_count++;
		}
		lp_err(lpi, "=== IOV DUMP END: %lu IOVs total ===\n", iov_count);
	}

	lpi->buf_size = 4*1024*1024;
	if (posix_memalign(&lpi->buf, PAGE_SIZE, lpi->buf_size))
	{
		lp_err(lpi, "posix_memalign ERROR\n");
		goto free_iovs;
	}

	ret = nr_pages;
	goto free_mm;

free_iovs:
	free_iovs(lpi);
free_mm:
	mm_entry__free_unpacked(mm, NULL);

	return ret;
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, unsigned long nr);
static int uffd_io_complete_bulk(struct page_read *pr, unsigned long vaddr, unsigned long nr);

static int ud_open(int client, struct lazy_pages_info **_lpi)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int pr_flags = PR_TASK;

	lpi = lpi_init();
	if (!lpi)
		goto out;

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &lpi->pid, sizeof(lpi->pid), 0);
	if (ret != sizeof(lpi->pid)) {
		if (ret < 0)
			pr_perror("PID recv error");
		else
			pr_err("PID recv: short read\n");
		goto out;
	}

	if (lpi->pid < 0) {
		pr_debug("Zombie PID: %d\n", lpi->pid);
		lpi_fini(lpi);
		return 0;
	}

	lpi->lpfd.fd = recv_fd(client);
	if (lpi->lpfd.fd < 0) {
		pr_err("recv_fd error\n");
		goto out;
	}
	pr_err("Received PID: %d, uffd: %d\n", lpi->pid, lpi->lpfd.fd);

	if (opts.use_page_server)
		pr_flags |= PR_REMOTE;
	ret = open_page_read(lpi->pid, &lpi->pr, pr_flags);
	if (ret <= 0) {
		lp_err(lpi, "Failed to open pagemap\n");
		goto out;
	}

	if (opts.cow_dump) {
		/* Bulk mode: pages arrive automatically from background thread */
		lpi->pr.io_complete = uffd_io_complete_bulk;
	} else {
		/* On-demand mode: manage individual page requests */
		lpi->pr.io_complete = uffd_io_complete;
	}

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	ret = collect_iovs(lpi);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	lp_debug(lpi, "Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	list_add_tail(&lpi->l, &lpis);
	*_lpi = lpi;

	return 0;

out:
	lpi_fini(lpi);
	return -1;
}

static int handle_exit(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "EXIT\n");
	if (epoll_del_rfd(epollfd, &lpi->lpfd))
		return -1;
	free_iovs(lpi);
	close(lpi->lpfd.fd);
	lpi->lpfd.fd = -lpi->lpfd.fd;
	lpi->exited = true;

	/* keep it for tracking in-flight requests and for the summary */
	list_move_tail(&lpi->l, &lpis);

	return 0;
}

static bool uffd_recoverable_error(int mcopy_rc)
{
	if (errno == EAGAIN || errno == ENOENT || errno == EEXIST)
		return true;

	if (mcopy_rc == -ENOENT || mcopy_rc == -EEXIST)
		return true;

	return false;
}

static int uffd_check_op_error(struct lazy_pages_info *lpi, const char *op, unsigned long *nr_pages, long mcopy_rc)
{
	if (errno == ENOSPC || errno == ESRCH) {
		lp_err(lpi, "uffd_copy1:ERROR errno=%d\n", errno);
		handle_exit(lpi);
		return -1;
	}

	if (!uffd_recoverable_error(mcopy_rc)) {
		lp_perror(lpi, "%s: mcopy_rc:%ld\n", op, mcopy_rc);
		return -1;
	}

	lp_debug(lpi, "%s: mcopy_rc:%ld, errno:%d\n", op, mcopy_rc, errno);

	if (mcopy_rc <= 0)
		*nr_pages = 0;
	else
		*nr_pages = mcopy_rc / PAGE_SIZE;

	return 0;
}

static int xfer_pages(struct lazy_pages_info *lpi);


/*
 * Queue an EAGAIN request for later retry in COW dump mode.
 * For copy operations, buf should point to the data to copy.
 * For zero operations, buf should be NULL.
 */
static int queue_eagain_request(struct lazy_pages_info *lpi, __u64 address, 
                                unsigned long nr_pages, void *buf, const char *op_name)
{
	struct uffd_eagain_request *req;
	void *buf_copy = NULL;
	unsigned long len = nr_pages * page_size();
	
	lp_debug(lpi, "uffd_%s EAGAIN in COW mode: queueing 0x%llx/%ld for later\n",
		 op_name, address, len);
	
	/* Copy buffer if provided (copy operation) */
	if (buf) {
		buf_copy = xmalloc(len);
		if (!buf_copy) {
			lp_err(lpi, "Failed to allocate buffer for EAGAIN request\n");
			return -1;
		}
		memcpy(buf_copy, buf, len);
	}
	
	/* Create request entry */
	req = xmalloc(sizeof(*req));
	if (!req) {
		if (buf_copy)
			xfree(buf_copy);
		return -1;
	}
	
	req->lpi = lpi;
	req->address = address;
	req->nr_pages = nr_pages;
	req->buf = buf_copy;  /* NULL for zero operations */
	INIT_LIST_HEAD(&req->l);
	
	list_add_tail(&req->l, &eagain_requests);
	
	return 0;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, unsigned long *nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = *nr_pages * page_size();
	
	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);

	if (ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy) == -1) {
		/* In COW dump mode, queue EAGAIN requests instead of blocking */
		if (errno == EAGAIN && opts.cow_dump)
			return queue_eagain_request(lpi, address, *nr_pages, lpi->buf, "copy");
		
		/* Non-COW mode or non-EAGAIN: check for other errors */
		if (uffd_check_op_error(lpi, "copy", nr_pages, uffdio_copy.copy)) {
			lp_err(lpi, "UFFDIO_COPY got error\n");
			return -1;
		}

		/* If uffd_check_op_error handled it (e.g., ENOSPC/ESRCH), return success */
		return 0;
	}

	if (uffdio_copy.copy < 0) {
		/* Soft userfaultfd error: encoded as -errno in copy */
		errno = -uffdio_copy.copy;

		/* In COW dump mode, queue EAGAIN requests */
		if (errno == EAGAIN && opts.cow_dump)
			return queue_eagain_request(lpi, address, *nr_pages, lpi->buf, "copy");

		if (uffd_check_op_error(lpi, "copy", nr_pages, uffdio_copy.copy)) {
			lp_err(lpi, "UFFDIO_COPY err \n");
			return -1;
		}
		return 0;
	}

	/* Success */
	if (uffdio_copy.copy == 0) {
		lp_err(lpi, "UFFDIO_COPY copied 0 bytes at 0x%llx\n", uffdio_copy.dst);
		*nr_pages = 0;
	}

	lpi->copied_pages += *nr_pages;
	return 0;
}

static int uffd_io_complete(struct page_read *pr, unsigned long img_addr, unsigned long nr)
{
	struct lazy_pages_info *lpi;
	unsigned long addr = 0, req_pages;
	struct lazy_iov *req;
	int ret;

	lpi = container_of(pr, struct lazy_pages_info, pr);
	pr_err("uffd_io_complete\n");
	/*
	 * The process may exit while we still have requests in
	 * flight. We just drop the request and the received data in
	 * this case to avoid making uffd unhappy
	 */
	if (lpi->exited)
		return 0;

	list_for_each_entry(req, &lpi->reqs, l) {
		if (req->img_start == img_addr) {
			addr = req->start;
			break;
		}
	}

	/* the request may be already gone because if unmap/remove */
	if (!addr)
		return 0;

	/*
	 * By the time we get the pages from the remote source, parts
	 * of the request may already be gone because of unmap/remove
	 * OTOH, the remote side may send less pages than we requested.
	 * Make sure we are not trying to uffd_copy more memory than
	 * we should.
	 */
	req_pages = (req->end - req->start) / PAGE_SIZE;
	nr = min(nr, req_pages);

	ret = uffd_copy(lpi, addr, &nr);
	if (ret < 0)
		return ret;

	/* recheck if the process exited, it may be detected in uffd_copy */
	if (lpi->exited)
		return 0;

	/*
	 * Since the completed request length may differ from the
	 * actual data we've received we re-insert the request to IOVs
	 * list and let drop_iovs do the range math, free memory etc.
	 */
	iov_list_insert(req, &lpi->iovs);
	ret = drop_iovs(lpi, addr, nr * PAGE_SIZE);

	
	return ret;
}

static int uffd_io_complete_bulk(struct page_read *pr, unsigned long vaddr, unsigned long nr)
{
	struct lazy_pages_info *lpi;
	unsigned long pages = nr;
	unsigned long tracked_pages;
	struct lazy_iov *iov;
	int ret;
	struct timespec t_start, t_copy, t_drop, t_end;
	uffd_stats.io_complete_bulk_count_start++;
	
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	lpi = container_of(pr, struct lazy_pages_info, pr);

	/* Process may exit while pages are in flight */
	if (lpi->exited) {
		lp_debug(lpi, "Page at 0x%lx no longer needed existed\n", vaddr);
		return 0;
	}

	/* Check if this address is still tracked (not removed/unmapped) */
	/* First check main IOVs list */
	iov = find_iov(lpi, vaddr);

	/* If not found in main list, check requests list (may have been queued by page fault) */
	if (!iov) {
		list_for_each_entry(iov, &lpi->reqs, l) {
			if (vaddr >= iov->start && vaddr < iov->end) {
				lp_debug(lpi, "Page at 0x%lx found in requests list\n", vaddr);
				goto found_iov;
			}
		}
		iov = NULL; /* Reset if not found in reqs either */
	}

	if (!iov) {
#if 0
		struct lazy_iov *tmp_iov;
		unsigned long iovs_count = 0;
		unsigned long reqs_count = 0;
#endif

		lp_debug(lpi, "Page at 0x%lx no longer needed (unmapped), dropping\n", vaddr);
#if 0	
		/* Dump all IOVs to understand what happened */
		lp_err(lpi, "=== IOV STATE DUMP (address 0x%lx not found) ===\n", vaddr);
		
		lp_err(lpi, "Main IOVs list:\n");
		list_for_each_entry(tmp_iov, &lpi->iovs, l) {
			lp_err(lpi, "  IOV[%lu]: 0x%lx-0x%lx (img_start=0x%lx, len=%lu, pages=%lu)\n",
				iovs_count, tmp_iov->start, tmp_iov->end, tmp_iov->img_start,
				tmp_iov->end - tmp_iov->start, (tmp_iov->end - tmp_iov->start) / PAGE_SIZE);
			iovs_count++;
		}
		
		lp_err(lpi, "Requests list:\n");
		list_for_each_entry(tmp_iov, &lpi->reqs, l) {
			lp_err(lpi, "  REQ[%lu]: 0x%lx-0x%lx (img_start=0x%lx, len=%lu, pages=%lu)\n",
				reqs_count, tmp_iov->start, tmp_iov->end, tmp_iov->img_start,
				tmp_iov->end - tmp_iov->start, (tmp_iov->end - tmp_iov->start) / PAGE_SIZE);
			reqs_count++;
		}
		
		lp_err(lpi, "=== IOV DUMP END: %lu main IOVs, %lu requests ===\n", iovs_count, reqs_count);
#endif
		return 0; /* Silently ignore - region was unmapped */
	}

found_iov:
	tracked_pages = (iov->end - vaddr) / PAGE_SIZE;
	pages = min(pages, tracked_pages);
	if (!pages)
		return 0;

	/* Copy pages to userspace */
	ret = uffd_copy(lpi, vaddr, &pages);
	clock_gettime(CLOCK_MONOTONIC, &t_copy);
	uffd_stats.uffd_copy_total_ns += (t_copy.tv_sec - t_start.tv_sec) * 1000000000 + (t_copy.tv_nsec - t_start.tv_nsec);
	uffd_stats.uffd_copy_count++;

	if (ret < 0)
		return ret;

	/* Recheck if process exited (may be detected in uffd_copy) */
	if (lpi->exited)
		return 0;

	ret = drop_iovs(lpi, vaddr, pages * PAGE_SIZE);
	if (ret < 0)
		return ret;
	clock_gettime(CLOCK_MONOTONIC, &t_drop);
	uffd_stats.drop_iovs_total_ns += (t_drop.tv_sec - t_copy.tv_sec) * 1000000000 + (t_drop.tv_nsec - t_copy.tv_nsec);
	uffd_stats.drop_iovs_count++;

	clock_gettime(CLOCK_MONOTONIC, &t_end);
	uffd_stats.io_complete_bulk_total_ns += (t_end.tv_sec - t_start.tv_sec) * 1000000000 + (t_end.tv_nsec - t_start.tv_nsec);
	uffd_stats.io_complete_bulk_count++;

	return ret;
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, unsigned long nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;
	uffdio_zeropage.zeropage = 0;

	lp_err(lpi, "zero page at 0x%llx\n", address);
	
	if (ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage) == -1) {
		/* In COW dump mode, queue EAGAIN requests instead of blocking */
		if (errno == EAGAIN && opts.cow_dump)
			return queue_eagain_request(lpi, address, nr_pages, NULL, "zero");
		
		/* Non-COW mode or non-EAGAIN: check for errors */
		if (uffd_check_op_error(lpi, "zero", &nr_pages, uffdio_zeropage.zeropage))
			return -1;
			
		return 0;
	}
	
	/* Check for soft error */
	if (uffdio_zeropage.zeropage < 0) {
		errno = -uffdio_zeropage.zeropage;
		
		/* In COW dump mode, queue EAGAIN requests */
		if (errno == EAGAIN && opts.cow_dump)
			return queue_eagain_request(lpi, address, nr_pages, NULL, "zero");
		
		if (uffd_check_op_error(lpi, "zero", &nr_pages, uffdio_zeropage.zeropage))
			return -1;
			
		return 0;
	}

	return 0;
}

/*
 * Seek for the requested address in the pagemap. If it is found, the
 * subsequent call to pr->page_read will bring us the data. If the
 * address is not found in the pagemap, but no error occurred, the
 * address should be mapped to zero pfn.
 *
 * Returns 0 for zero pages, 1 for "real" pages and negative value on
 * error
 */
static int uffd_seek_pages(struct lazy_pages_info *lpi, __u64 address, unsigned long nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret) {
		lp_err(lpi, "no pagemap covers %llx\n", address);
		return -1;
	}

	return 0;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, unsigned long nr, unsigned flags)
{
	int ret;

	ret = uffd_seek_pages(lpi, address, nr);
	if (ret) {
		lp_warn(lpi, "#PF at 0x%llx uffd_seek_pages failed\n", address);
		return ret;
	}

	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		lp_err(lpi, "failed reading pages at %llx\n", address);
		return ret;
	}

	return 0;
}

static struct lazy_iov *pick_next_range(struct lazy_pages_info *lpi)
{
	return list_first_entry(&lpi->iovs, struct lazy_iov, l);
}

/*
 * This is very simple heurstics for background transfer control.
 * The idea is to transfer larger chunks when there is no page faults
 * and drop the background transfer size each time #PF occurs to some
 * default value. The default is empirically set to 64Kbytes
 */
static void update_xfer_len(struct lazy_pages_info *lpi, bool pf)
{
	if (pf)
		lpi->xfer_len = DEFAULT_XFER_LEN;
	else
		lpi->xfer_len += DEFAULT_XFER_LEN;

	if (lpi->xfer_len > MAX_XFER_LEN)
		lpi->xfer_len = MAX_XFER_LEN;
}

static int xfer_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;
	unsigned long nr_pages;
	unsigned long len;
	int err;
	int bucket;

	iov = pick_next_range(lpi);
	if (!iov)
		return 0;

	len = min(iov->end - iov->start, lpi->xfer_len);

	iov = extract_range(iov, iov->start, iov->start + len);
	if (!iov)
		return -1;
	list_move(&iov->l, &lpi->reqs);

	nr_pages = (iov->end - iov->start) / PAGE_SIZE;

	/* Update statistics */
	uffd_stats.total_bg_reqs++;
	uffd_stats.total_pages += nr_pages;
	bucket = get_histogram_bucket(nr_pages);
	uffd_stats.bg_hist[bucket]++;

	update_xfer_len(lpi, false);

	err = uffd_handle_pages(lpi, iov->img_start, nr_pages, PR_ASYNC | PR_ASAP);
	if (err < 0) {
		lp_err(lpi, "Error during UFFD copy\n");
		return -1;
	}

	return 0;
}

static int handle_remove(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct uffdio_range unreg;

	unreg.start = msg->arg.remove.start;
	unreg.len = msg->arg.remove.end - msg->arg.remove.start;

	lp_debug(lpi, "%s: %llx(%llx)\n", msg->event == UFFD_EVENT_REMOVE ? "REMOVE" : "UNMAP",
		 unreg.start, unreg.len);

	/*
	 * The REMOVE event does not change the VMA, so we need to
	 * make sure that we won't handle #PFs in the removed
	 * range. With UNMAP, there's no VMA to worry about
	 */

	 if (msg->event == UFFD_EVENT_REMOVE && ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
		/*
		 * The kernel returns -ENOMEM when unregister is
		 * called after the process has gone
		 */
		if (errno == ENOMEM) {
			handle_exit(lpi);
			return 0;
		}

		pr_perror("Failed to unregister (%llx - %llx)", unreg.start, unreg.start + unreg.len);
		return -1;
	}

	return drop_iovs(lpi, unreg.start, unreg.len);

}

static int handle_remap(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	unsigned long from = msg->arg.remap.from;
	unsigned long to = msg->arg.remap.to;
	unsigned long len = msg->arg.remap.len;

	lp_debug(lpi, "REMAP: %lx -> %lx (%ld)\n", from, to, len);

	return remap_iovs(lpi, from, to, len);
}

static int handle_fork(struct lazy_pages_info *parent_lpi, struct uffd_msg *msg)
{
	struct lazy_pages_info *lpi;
	int uffd = msg->arg.fork.ufd;

	lp_debug(parent_lpi, "FORK: child with ufd=%d\n", uffd);

	lpi = lpi_init();
	if (!lpi)
		return -1;

	if (copy_iovs(parent_lpi, lpi))
		goto out;

	lpi->pid = parent_lpi->pid;
	lpi->lpfd.fd = uffd;
	lpi->parent = parent_lpi->parent ? parent_lpi->parent : parent_lpi;
	lpi->copied_pages = lpi->parent->copied_pages;
	lpi->total_pages = lpi->parent->total_pages;
	list_add_tail(&lpi->l, &pending_lpis);

	dup_page_read(&lpi->parent->pr, &lpi->pr);

	lpi_get(lpi->parent);

	page_read_disable_dedup(&parent_lpi->pr);
	page_read_disable_dedup(&lpi->pr);
	return 1;

out:
	lpi_fini(lpi);
	return -1;
}

/*
 * We may exit epoll_run_rfds() loop because of non-fork() event. In
 * such case we return 1 rather than 0 to let the caller know that no
 * fork() events were pending
 */
static int complete_forks(int epollfd, struct epoll_event **events, int *nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	struct epoll_event *tmp;

	if (list_empty(&pending_lpis))
		return 1;

	list_for_each_entry(lpi, &pending_lpis, l)
		(*nr_fds)++;

	tmp = xrealloc(*events, sizeof(struct epoll_event) * (*nr_fds));
	if (!tmp)
		return -1;
	*events = tmp;

	list_for_each_entry_safe(lpi, n, &pending_lpis, l) {
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			return -1;

		list_del_init(&lpi->l);
		list_add_tail(&lpi->l, &lpis);
	}

	return 0;
}

static bool is_page_queued(struct lazy_pages_info *lpi, unsigned long addr)
{
	struct lazy_iov *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (addr >= req->start && addr < req->end)
			return true;

	return false;
}

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lazy_iov *iov;
	__u64 address;
	int ret;
	unsigned long nr_pages;
	int bucket;

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_warn(lpi, "#PF at 0x%llx\n", address);

	if (is_page_queued(lpi, address)) {
		lp_warn(lpi, "#PF at 0x%llx queued\n", address);
		return 0;
	}

	iov = find_iov(lpi, address);
	if (!iov) {
		lp_warn(lpi, "#PF at 0x%llx !iov\n", address);
		return uffd_zero(lpi, address, 1);
	}

	iov = extract_range(iov, address, address + PAGE_SIZE);
	if (!iov) {
		lp_warn(lpi, "#PF at 0x%llx !iov2\n", address);
		return -1;
	}

	list_move(&iov->l, &lpi->reqs);

	nr_pages = (iov->end - iov->start) / PAGE_SIZE;

	/* Update statistics */
	uffd_stats.total_pf_reqs++;
	uffd_stats.total_pages += nr_pages;
	bucket = get_histogram_bucket(nr_pages);
	uffd_stats.pf_hist[bucket]++;

	update_xfer_len(lpi, true);

	ret = uffd_handle_pages(lpi, iov->img_start, nr_pages, PR_ASYNC | PR_ASAP);
	if (ret < 0) {
		lp_err(lpi, "Error during regular page copy\n");
		return -1;
	}

	return 0;
}

static int handle_uffd_event(struct epoll_rfd *lpfd)
{
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	int ret;

	lpi = container_of(lpfd, struct lazy_pages_info, lpfd);

	ret = read(lpfd->fd, &msg, sizeof(msg));
	if (ret < 0) {
		/* we've already handled the page fault for another thread */
		if (errno == EAGAIN)
			return 0;
		if (errno == EBADF && lpi->exited) {
			lp_debug(lpi, "excess message in queue: %d", msg.event);
			return 0;
		}
		lp_perror(lpi, "Can't read uffd message");
		return -1;
	} else if (ret == 0) {
		return 1;
	} else if (ret != sizeof(msg)) {
		lp_err(lpi, "Can't read uffd message: short read");
		return -1;
	}

	switch (msg.event) {
	case UFFD_EVENT_PAGEFAULT:
		return handle_page_fault(lpi, &msg);
	case UFFD_EVENT_REMOVE:
	case UFFD_EVENT_UNMAP:
		return handle_remove(lpi, &msg);
	case UFFD_EVENT_REMAP:
		return handle_remap(lpi, &msg);
	case UFFD_EVENT_FORK:
		return handle_fork(lpi, &msg);
	default:
		lp_err(lpi, "unexpected uffd event %u\n", msg.event);
		return -1;
	}

	return 0;
}

static void lazy_pages_summary(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "UFFD transferred pages: (%ld/%ld)\n", lpi->copied_pages, lpi->total_pages);

#if 0
	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		lp_warn(lpi, "Only %ld of %ld pages transferred via UFFD\n"
			"Something probably went wrong.\n",
			lpi->copied_pages, lpi->total_pages);
		return 1;
	}
#endif
}

/*
 * Retry a copy operation that previously failed with EAGAIN.
 * Returns: 0 on success, -EAGAIN if still blocked, -1 on error
 */
static int retry_uffd_copy(struct uffd_eagain_request *req)
{
	struct uffdio_copy uffdio_copy;
	
	uffdio_copy.dst = req->address;
	uffdio_copy.src = (unsigned long)req->buf;
	uffdio_copy.len = req->nr_pages * page_size();
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	if (ioctl(req->lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy) == -1) {
		if (errno == EAGAIN)
			return -EAGAIN;
		
		lp_err(req->lpi, "EAGAIN copy retry failed for 0x%llx: %d\n", 
		       req->address, errno);
		return -1;
	}

	/* Check for soft error */
	if (uffdio_copy.copy < 0) {
		errno = -uffdio_copy.copy;
		if (errno == EAGAIN)
			return -EAGAIN;
		
		lp_err(req->lpi, "EAGAIN copy retry soft error for 0x%llx: %d\n",
		       req->address, errno);
		return -1;
	}

	/* Success */
	req->lpi->copied_pages += req->nr_pages;
	lp_debug(req->lpi, "EAGAIN copy retry succeeded for 0x%llx\n", req->address);
	return 0;
}

/*
 * Retry a zero operation that previously failed with EAGAIN.
 * Returns: 0 on success, -EAGAIN if still blocked, -1 on error
 */
static int retry_uffd_zero(struct uffd_eagain_request *req)
{
	struct uffdio_zeropage uffdio_zeropage;
	
	uffdio_zeropage.range.start = req->address;
	uffdio_zeropage.range.len = req->nr_pages * page_size();
	uffdio_zeropage.mode = 0;
	uffdio_zeropage.zeropage = 0;

	if (ioctl(req->lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage) == -1) {
		if (errno == EAGAIN)
			return -EAGAIN;
		
		lp_err(req->lpi, "EAGAIN zero retry failed for 0x%llx: %d\n", 
		       req->address, errno);
		return -1;
	}

	/* Check for soft error */
	if (uffdio_zeropage.zeropage < 0) {
		errno = -uffdio_zeropage.zeropage;
		if (errno == EAGAIN)
			return -EAGAIN;
		
		lp_err(req->lpi, "EAGAIN zero retry soft error for 0x%llx: %d\n",
		       req->address, errno);
		return -1;
	}

	/* Success */
	lp_debug(req->lpi, "EAGAIN zero retry succeeded for 0x%llx\n", req->address);
	return 0;
}

/*
 * Process pending EAGAIN requests.
 * Attempts to retry UFFDIO_COPY or UFFDIO_ZEROPAGE for requests that previously failed with EAGAIN.
 */
int process_eagain_requests(void)
{
	struct uffd_eagain_request *req, *n;
	int ret;
	struct timespec t_start, t_end;

	clock_gettime(CLOCK_MONOTONIC, &t_start);

	list_for_each_entry_safe(req, n, &eagain_requests, l) {
		/* Skip if process has exited */
		if (req->lpi->exited) {
			uffd_stats.eagain_skipped++;
			list_del(&req->l);
			if (req->buf)
				xfree(req->buf);
			xfree(req);
			continue;
		}

		uffd_stats.eagain_processed++;

		/* Call appropriate retry function based on operation type */
		if (req->buf)
			ret = retry_uffd_copy(req);
		else
			ret = retry_uffd_zero(req);

		if (ret == -EAGAIN) {
			/* Still blocked - keep in queue for next attempt */
			uffd_stats.eagain_blocked++;
			continue;
		} else if (ret < 0) {
			/* Error - remove from queue */
			uffd_stats.eagain_errors++;
			list_del(&req->l);
			if (req->buf)
				xfree(req->buf);
			xfree(req);
			continue;
		}

		/* Success! */
		uffd_stats.eagain_succeeded++;

		/* Clean up and remove from queue */
		list_del(&req->l);
		if (req->buf)
			xfree(req->buf);
		xfree(req);
	}

	clock_gettime(CLOCK_MONOTONIC, &t_end);
	uffd_stats.eagain_total_ns += (t_end.tv_sec - t_start.tv_sec) * 1000000000 + (t_end.tv_nsec - t_start.tv_nsec);
	uffd_stats.eagain_calls++;

	return 0;
}

static int handle_requests(int epollfd, struct epoll_event **events, int nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	int poll_timeout = -1;
	int ret;

	for (;;) {

		ret = epoll_run_rfds(epollfd, *events, nr_fds, poll_timeout);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			ret = complete_forks(epollfd, events, &nr_fds);
			if (ret < 0)
				goto out;
			if (restore_finished)
				poll_timeout = 0;
			if (!restore_finished || !ret)
				continue;
		}

		/* make sure we return success if there is nothing to xfer */
		ret = 0;
		if (!opts.cow_dump) {
		list_for_each_entry_safe(lpi, n, &lpis, l) {
			if (!list_empty(&lpi->iovs) && list_empty(&lpi->reqs)) {
				ret = xfer_pages(lpi);
				if (ret < 0)
					goto out;
				break;
			}

			if (list_empty(&lpi->reqs)) {
				lazy_pages_summary(lpi);
				list_del(&lpi->l);
				lpi_put(lpi);
			}
		}
		}
		if (!opts.cow_dump && list_empty(&lpis))
			break;
	}

out:
	return ret;
}

int lazy_pages_finish_restore(void)
{
	uint32_t fin = LAZY_PAGES_RESTORE_FINISHED;
	int fd, ret;

	if (!opts.lazy_pages)
		return 0;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("No lazy-pages socket\n");
		return -1;
	}

	ret = send(fd, &fin, sizeof(fin), 0);
	if (ret != sizeof(fin)) {
		if (ret < 0 && errno == EPIPE) {
			pr_warn("Lazy-pages socket closed before finish; assuming transfer complete\n");
			close(fd);
			return 0;
		}
		pr_perror("Failed sending restore finished indication");
		close(fd);
		return -1;
	}

	close(fd);

	return ret < 0 ? ret : 0;
}

static int prepare_lazy_socket(void)
{
	int listen;
	struct sockaddr_un saddr;

	if (prepare_sock_addr(&saddr))
		return -1;

	pr_debug("Waiting for incoming connections on %s\n", saddr.sun_path);
	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	return listen;
}

static int lazy_sk_read_event(struct epoll_rfd *rfd)
{
	uint32_t fin;
	int ret;

	ret = recv(rfd->fd, &fin, sizeof(fin), 0);
	/*
	 * epoll sets POLLIN | POLLHUP for the EOF case, so we get short
	 * read just before hangup_event
	 */
	if (!ret)
		return 0;

	if (ret != sizeof(fin)) {
		pr_perror("Failed getting restore finished indication");
		return -1;
	}

	if (fin != LAZY_PAGES_RESTORE_FINISHED) {
		pr_err("Unexpected response: %x\n", fin);
		return -1;
	}

	restore_finished = true;

	return 1;
}

static int lazy_sk_hangup_event(struct epoll_rfd *rfd)
{
	if (!restore_finished) {
		pr_err("Restorer unexpectedly closed the connection\n");
		return -1;
	}

	return 0;
}

static int prepare_uffds(int listen, int epollfd)
{
	int i;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *)&saddr, &len)) < 0) {
		pr_perror("server_accept error");
		close(listen);
		return -1;
	}

	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi = NULL;
		if (ud_open(client, &lpi))
			goto close_uffd;
		if (lpi == NULL)
			continue;
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			goto close_uffd;
	}

	lazy_sk_rfd.fd = client;
	lazy_sk_rfd.read_event = lazy_sk_read_event;
	lazy_sk_rfd.hangup_event = lazy_sk_hangup_event;
	if (epoll_add_rfd(epollfd, &lazy_sk_rfd))
		goto close_uffd;

	close(listen);
	return 0;

close_uffd:
	close_safe(&client);
	close(listen);
	return -1;
}
extern int page_server_start_async_read_bulk(void *buf, unsigned long nr_pages, 
					      ps_async_read_complete complete, void *priv);
int cr_lazy_pages(bool daemon)
{
	struct epoll_event *events = NULL;
	int nr_fds;
	int lazy_sk;
	int ret;

	if (!kdat.has_uffd)
		return -1;

	if (prepare_dummy_pstree())
		return -1;

	lazy_sk = prepare_lazy_socket();
	if (lazy_sk < 0)
		return -1;

	if (daemon) {
		ret = cr_daemon(1, 0, -1);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			return -1;
		}
		if (ret > 0) { /* parent task, daemon started */
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					return -1;
				}
			}

			return 0;
		}
	}

	if (status_ready())
		return -1;

	/*
	 * we poll nr_tasks userfault fds, UNIX socket between lazy-pages
	 * daemon and the cr-restore, and, optionally TCP socket for
	 * remote pages
	 */
	nr_fds = task_entries->nr_tasks + (opts.use_page_server ? 2 : 1);
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(lazy_sk, epollfd)) {
		xfree(events);
		return -1;
	}

	if (opts.use_page_server) {
		struct lazy_pages_info *lpi;

		if (connect_to_page_server_to_recv(epollfd)) {
			xfree(events);
			return -1;
		}

		/* Now that socket is connected, request all pages for bulk mode */
		if (opts.cow_dump) {
			list_for_each_entry(lpi, &lpis, l) {
				pr_info("Requesting all remote pages for pid=%d\n", lpi->pid);
				if (request_all_remote_pages(lpi->pr.img_id) < 0) {
					pr_err("Failed to request all remote pages for pid=%d\n", lpi->pid);
					xfree(events);
					return -1;
				}
			}
		}
	}

	ret = handle_requests(epollfd, &events, nr_fds);

	disconnect_from_page_server();

	xfree(events);
	return ret;
}
