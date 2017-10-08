#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
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
#include "util.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "uffd: "

#define lp_debug(lpi, fmt, arg...) pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...) pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...) pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...) pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

#define NEED_UFFD_API_FEATURES (UFFD_FEATURE_EVENT_FORK |	    \
				UFFD_FEATURE_EVENT_REMAP |	    \
				UFFD_FEATURE_EVENT_UNMAP |	    \
				UFFD_FEATURE_EVENT_REMOVE)

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

static mutex_t *lazy_sock_mutex;

struct lazy_iov {
	struct list_head l;
	unsigned long base;	/* run-time start address, tracks remaps */
	unsigned long img_base;	/* start address at the dump time */
	unsigned long len;
	bool queued;
};

struct lp_req {
	unsigned long addr;	/* actual #PF (or background) destination */
	unsigned long img_addr;	/* the corresponding address at the dump time */
	unsigned long len;
	struct list_head l;
};

struct lazy_pages_info {
	int pid;

	struct list_head iovs;
	struct list_head reqs;

	struct lazy_pages_info *parent;
	unsigned num_children;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	void *buf;
};

/* global lazy-pages daemon state */
static LIST_HEAD(lpis);
static LIST_HEAD(exiting_lpis);
static LIST_HEAD(pending_lpis);
static int epollfd;

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
	lpi->lpfd.revent = handle_uffd_event;

	return lpi;
}

static void free_iovs(struct lazy_pages_info *lpi)
{
	struct lazy_iov *p, *n;

	list_for_each_entry_safe(p, n, &lpi->iovs, l) {
		list_del(&p->l);
		xfree(p);
	}
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	if (!lpi)
		return;
	free(lpi->buf);
	free_iovs(lpi);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->parent)
		lpi->parent->num_children--;
	if (!lpi->parent && !lpi->num_children && lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	free(lpi);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	int len;

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path),
		       "%s", LAZY_PAGES_SOCK_NAME);
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

	fd = get_service_fd(LAZY_PAGES_SK_OFF);
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

int uffd_open(int flags, unsigned long *features)
{
	struct uffdio_api uffdio_api = { 0 };
	int uffd;

	uffd = syscall(SYS_userfaultfd, flags);
	if (uffd == -1) {
		pr_perror("Lazy pages are not available");
		return -errno;
	}

	uffdio_api.api = UFFD_API;
	if (features)
		uffdio_api.features = *features;

	if (ioctl(uffd, UFFDIO_API, &uffdio_api)) {
		pr_perror("Failed to get uffd API");
		goto err;
	}

	if (uffdio_api.api != UFFD_API) {
		pr_err("Incompatible uffd API: expected %Lu, got %Lu\n",
		       UFFD_API, uffdio_api.api);
		goto err;
	}

	if (features)
		*features = uffdio_api.features;

	return uffd;

err:
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
	task_args->uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &features);
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
	int fd, new_fd;
	int len;
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

	new_fd = install_service_fd(LAZY_PAGES_SK_OFF, fd);
	close(fd);
	if (new_fd < 0)
		return -1;

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (connect(new_fd, (struct sockaddr *) &sun, len) < 0) {
		pr_perror("connect to %s failed", sun.sun_path);
		close(new_fd);
		return -1;
	}

	return 0;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(saddr->sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(saddr->sun_path);

	if (bind(fd, (struct sockaddr *) saddr, len) < 0) {
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

static struct lazy_iov *find_iov(struct lazy_pages_info *lpi,
				 unsigned long addr)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &lpi->iovs, l)
		if (addr >= iov->base && addr < iov->base + iov->len)
			return iov;

	return NULL;
}

static int split_iov(struct lazy_iov *iov, unsigned long addr, bool new_below)
{
	struct lazy_iov *new;

	new = xzalloc(sizeof(*new));
	if (!new)
		return -1;

	if (new_below) {
		new->base = iov->base;
		new->img_base = iov->img_base;
		new->len = addr - iov->base;
		iov->base = addr;
		iov->img_base += new->len;
		iov->len -= new->len;
		list_add_tail(&new->l, &iov->l);
	} else {
		new->base = addr;
		new->img_base = iov->img_base + addr - iov->base;
		new->len = iov->len - (addr - iov->base);
		iov->len -= new->len;
		list_add(&new->l, &iov->l);
	}

	return 0;
}

static int copy_iovs(struct lazy_pages_info *src, struct lazy_pages_info *dst)
{
	struct lazy_iov *iov, *new;
	int max_iov_len = 0;

	list_for_each_entry(iov, &src->iovs, l) {
		new = xzalloc(sizeof(*new));
		if (!new)
			return -1;

		new->base = iov->base;
		new->img_base = iov->img_base;
		new->len = iov->len;

		list_add_tail(&new->l, &dst->iovs);

		if (new->len > max_iov_len)
			max_iov_len = new->len;
	}

	if (posix_memalign(&dst->buf, PAGE_SIZE, max_iov_len))
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
static int drop_iovs(struct lazy_pages_info *lpi, unsigned long addr, int len)
{
	struct lazy_iov *iov, *n;

	list_for_each_entry_safe(iov, n, &lpi->iovs, l) {
		unsigned long start = iov->base;
		unsigned long end = start + iov->len;

		if (len <= 0 || addr + len < start)
			break;

		if (addr >= end)
			continue;

		if (addr < start) {
			len -= (start - addr);
			addr = start;
		}

		/*
		 * The range completely fits into the current IOV.
		 * If addr equals iov_base we just "drop" the
		 * beginning of the IOV. Otherwise, we make the IOV to
		 * end at addr, and add a new IOV start starts at
		 * addr + len.
		 */
		if (addr + len < end) {
			if (addr == start) {
				iov->base += len;
				iov->img_base += len;
				iov->len -= len;
			} else {
				if (split_iov(iov, addr + len, false))
					return -1;
				iov->len -= len;
			}
			break;
		}

		/*
		 * The range spawns beyond the end of the current IOV.
		 * If addr equals iov_base we just "drop" the entire
		 * IOV.  Otherwise, we cut the beginning of the IOV
		 * and continue to the next one with the updated range
		 */
		if (addr == start) {
			list_del(&iov->l);
			xfree(iov);
		} else {
			iov->len -= (end - addr);
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

static int remap_iovs(struct lazy_pages_info *lpi, unsigned long from,
		      unsigned long to, unsigned long len)
{
	unsigned long off = to - from;
	struct lazy_iov *iov, *n, *p;
	LIST_HEAD(remaps);

	list_for_each_entry_safe(iov, n, &lpi->iovs, l) {
		unsigned long iov_end = iov->base + iov->len;

		if (from >= iov_end)
			continue;

		if (len <= 0 || from + len < iov->base)
			break;

		if (from < iov->base) {
			len -= (iov->base - from);
			from = iov->base;
		}

		if (from > iov->base)
			if (split_iov(iov, from, true))
				return -1;
		if (from + len < iov_end)
			if (split_iov(iov, from + len, false))
				return -1;

		list_safe_reset_next(iov, n, l);

		/* here we have iov->base = from, iov_end <= from + len */
		from = iov_end;
		len -= iov->len;
		iov->base += off;
		list_move_tail(&iov->l, &remaps);
	}

	list_for_each_entry_safe(iov, n, &remaps, l) {
		list_for_each_entry(p, &lpi->iovs, l) {
			if (iov->base < p->base) {
				list_move_tail(&iov->l, &p->l);
				break;
			}
			if (list_is_last(&p->l, &lpi->iovs) &&
			    iov->base > p->base) {
				list_move(&iov->l, &p->l);
				break;
			}
		}
	}

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
	struct page_read *pr = &lpi->pr;
	struct lazy_iov *iov;
	MmEntry *mm;
	int nr_pages = 0, n_vma = 0, max_iov_len = 0;
	int ret = -1;
	unsigned long start, end, len;

	mm = init_mm_entry(lpi);
	if (!mm)
		return -1;

	while (pr->advance(pr)) {
		if (!pagemap_lazy(pr->pe))
			continue;

		start = pr->pe->vaddr;
		end = start + pr->pe->nr_pages * page_size();
		nr_pages += pr->pe->nr_pages;

		for (; n_vma < mm->n_vmas; n_vma++) {
			VmaEntry *vma = mm->vmas[n_vma];

			if (start >= vma->end)
				continue;

			iov = xzalloc(sizeof(*iov));
			if (!iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			iov->base = start;
			iov->img_base = start;
			iov->len = len;
			list_add_tail(&iov->l, &lpi->iovs);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->end)
				break;

			start = vma->end;
		}
	}

	if (posix_memalign(&lpi->buf, PAGE_SIZE, max_iov_len))
		goto free_iovs;

	ret = nr_pages;
	goto free_mm;

free_iovs:
	free_iovs(lpi);
free_mm:
	mm_entry__free_unpacked(mm, NULL);

	return ret;
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, int nr);

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
	pr_debug("Received PID: %d, uffd: %d\n", lpi->pid, lpi->lpfd.fd);

	if (opts.use_page_server)
		pr_flags |= PR_REMOTE;
	ret = open_page_read(lpi->pid, &lpi->pr, pr_flags);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	lpi->pr.io_complete = uffd_io_complete;

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
	lpi->lpfd.fd = 0;

	/* keep it for tracking in-flight requests and for the summary */
	list_move_tail(&lpi->l, &lpis);

	return 0;
}

static int uffd_check_op_error(struct lazy_pages_info *lpi, const char *op,
			       unsigned long len, unsigned long rc_len, int rc)
{
	if (rc) {
		if (errno == ENOSPC || errno == ESRCH) {
			handle_exit(lpi);
			return 0;
		}
		if (rc_len != -EEXIST) {
			lp_perror(lpi, "%s: rc:%d copy:%ld, errno:%d",
				 op, rc, rc_len, errno);
			return -1;
		}
	} else if (rc_len != len) {
		lp_err(lpi, "%s unexpected size %ld\n", op, rc_len);
		return -1;
	}

	return 0;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = nr_pages * page_size();
	int rc;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy);
	if (uffd_check_op_error(lpi, "copy", len, uffdio_copy.copy, rc))
		return -1;

	lpi->copied_pages += nr_pages;

	return 0;
}

static int uffd_io_complete(struct page_read *pr, unsigned long img_addr, int nr)
{
	struct lazy_pages_info *lpi;
	unsigned long addr = 0;
	struct lp_req *req;

	lpi = container_of(pr, struct lazy_pages_info, pr);

	list_for_each_entry(req, &lpi->reqs, l) {
		if (req->img_addr == img_addr) {
			addr = req->addr;
			list_del(&req->l);
			xfree(req);
			break;
		}
	}

	/*
	 * The process may exit while we still have requests in
	 * flight. We just drop the request and the received data in
	 * this case to avoid making uffd unhappy
	 */
	if (list_empty(&lpi->iovs))
	    return 0;

	BUG_ON(!addr);

	if (uffd_copy(lpi, addr, nr))
		return -1;

	return drop_iovs(lpi, addr, nr * PAGE_SIZE);
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;
	int rc;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	lp_debug(lpi, "zero page at 0x%llx\n", address);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	if (uffd_check_op_error(lpi, "zero", len, uffdio_zeropage.zeropage, rc))
		return -1;

	return 0;
}

/*
 * Seek for the requested address in the pagemap. If it is found, the
 * subsequent call to pr->page_read will bring us the data. If the
 * address is not found in the pagemap, but no error occured, the
 * address should be mapped to zero pfn.
 *
 * Returns 0 for zero pages, 1 for "real" pages and negative value on
 * error
 */
static int uffd_seek_pages(struct lazy_pages_info *lpi, __u64 address, int nr)
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

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr, unsigned flags)
{
	int ret;

	ret = uffd_seek_pages(lpi, address, nr);
	if (ret)
		return ret;

	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		lp_err(lpi, "failed reading pages at %llx\n", address);
		return ret;
	}

	return 0;
}

static struct lazy_iov *first_pending_iov(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &lpi->iovs, l)
		if (!iov->queued)
			return iov;

	return NULL;
}

static bool is_iov_queued(struct lazy_pages_info *lpi, struct lazy_iov *iov)
{
	struct lp_req *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (req->addr >= iov->base && req->addr < iov->base + iov->len)
			return true;

	return false;
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;
	struct lp_req *req;
	int nr_pages, err;

	iov = first_pending_iov(lpi);
	if (!iov)
		return 0;

	if (is_iov_queued(lpi, iov))
		return 0;

	nr_pages = iov->len / PAGE_SIZE;

	req = xzalloc(sizeof(*req));
	if (!req)
		return -1;

	req->addr = iov->base;
	req->img_addr = iov->img_base;
	req->len = iov->len;
	list_add(&req->l, &lpi->reqs);
	iov->queued = true;

	err = uffd_handle_pages(lpi, req->img_addr, nr_pages, PR_ASYNC | PR_ASAP);
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

	lp_debug(lpi, "%s: %Lx(%Lx)\n",
		 msg->event == UFFD_EVENT_REMOVE ? "REMOVE" : "UNMAP",
		 unreg.start, unreg.len);

	/*
	 * The REMOVE event does not change the VMA, so we need to
	 * make sure that we won't handle #PFs in the removed
	 * range. With UNMAP, there's no VMA to worry about
	 */
	if (msg->event == UFFD_EVENT_REMOVE &&
	    ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
		/*
		 * The kernel returns -ENOMEM when unregister is
		 * called after the process has gone
		 */
		if (errno == ENOMEM) {
			handle_exit(lpi);
			return 0;
		}

		pr_perror("Failed to unregister (%llx - %llx)", unreg.start,
			  unreg.start + unreg.len);
		return -1;
	}

	return drop_iovs(lpi, unreg.start, unreg.len);
}

static int handle_remap(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	unsigned long from = msg->arg.remap.from;
	unsigned long to = msg->arg.remap.to;
	unsigned long len = msg->arg.remap.len;

	lp_debug(lpi, "REMAP: %lx -> %lx (%ld)\n", from , to, len);

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

	lpi->parent->num_children++;

	return 1;

out:
	lpi_fini(lpi);
	return -1;
}

static int complete_forks(int epollfd, struct epoll_event **events, int *nr_fds)
{
	struct lazy_pages_info *lpi, *n;

	list_for_each_entry(lpi, &pending_lpis, l)
		(*nr_fds)++;

	*events = xrealloc(*events, sizeof(struct epoll_event) * (*nr_fds));
	if (!*events)
		return -1;

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
	struct lp_req *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (addr >= req->addr && addr < req->addr + req->len)
			return true;

	return false;
}

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lp_req *req;
	struct lazy_iov *iov;
	__u64 address;
	int ret;

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_debug(lpi, "#PF at 0x%llx\n", address);

	if (is_page_queued(lpi, address))
		return 0;

	iov = find_iov(lpi, address);
	if (!iov)
		return uffd_zero(lpi, address, 1);

	req = xzalloc(sizeof(*req));
	if (!req)
		return -1;
	req->addr = address;
	req->img_addr = iov->img_base + (address - iov->base);
	req->len = PAGE_SIZE;
	list_add(&req->l, &lpi->reqs);

	ret = uffd_handle_pages(lpi, req->img_addr, 1, PR_ASYNC | PR_ASAP);
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
	if (!ret)
		return 1;

	if (ret != sizeof(msg)) {
		/* we've already handled the page fault for another thread */
		if (errno == EAGAIN)
			return 0;
		if (ret < 0)
			lp_perror(lpi, "Can't read uffd message");
		else
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
	lp_debug(lpi, "UFFD transferred pages: (%ld/%ld)\n",
		 lpi->copied_pages, lpi->total_pages);

#if 0
	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		lp_warn(lpi, "Only %ld of %ld pages transferred via UFFD\n"
			"Something probably went wrong.\n",
			lpi->copied_pages, lpi->total_pages);
		return 1;
	}
#endif
}

#define POLL_TIMEOUT 1000

static int handle_requests(int epollfd, struct epoll_event *events, int nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	int poll_timeout = POLL_TIMEOUT;
	int ret;

	for (;;) {
		bool remaining = false;

		ret = epoll_run_rfds(epollfd, events, nr_fds, poll_timeout);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			if (complete_forks(epollfd, &events, &nr_fds))
				return -1;
			continue;
		}

		if (poll_timeout)
			pr_debug("Start handling remaining pages\n");

		poll_timeout = 0;
		list_for_each_entry_safe(lpi, n, &lpis, l) {
			if (list_empty(&lpi->iovs) && list_empty(&lpi->reqs)) {
				lazy_pages_summary(lpi);
				list_del(&lpi->l);
				lpi_fini(lpi);
				continue;
			}

			remaining = true;
			if (!list_empty(&lpi->iovs)) {
				ret = handle_remaining_pages(lpi);
				if (ret < 0)
					goto out;
				break;
			}
		}

		if (!remaining)
			break;
	}

out:
	return ret;

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

static int prepare_uffds(int listen, int epollfd)
{
	int i;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *) &saddr, &len)) < 0) {
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

	close_safe(&client);
	close(listen);
	return 0;

close_uffd:
	close_safe(&client);
	close(listen);
	return -1;
}

int cr_lazy_pages(bool daemon)
{
	struct epoll_event *events;
	int nr_fds;
	int lazy_sk;
	int ret;

	if (kerndat_uffd() || !kdat.has_uffd)
		return -1;

	if (prepare_dummy_pstree())
		return -1;

	lazy_sk = prepare_lazy_socket();
	if (lazy_sk < 0)
		return -1;

	if (daemon) {
		ret = cr_daemon(1, 0, &lazy_sk, -1);
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

	if (close_status_fd())
		return -1;

	nr_fds = task_entries->nr_tasks + (opts.use_page_server ? 1 : 0);
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(lazy_sk, epollfd))
		return -1;

	if (opts.use_page_server) {
		if (connect_to_page_server_to_recv(epollfd))
			return -1;
	}

	ret = handle_requests(epollfd, events, nr_fds);

	return ret;
}
