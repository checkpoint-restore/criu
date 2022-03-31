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
static int __drop_iovs(struct list_head *iovs, unsigned long addr, int len)
{
	struct lazy_iov *iov, *n;

	list_for_each_entry_safe(iov, n, iovs, l) {
		unsigned long start = iov->start;
		unsigned long end = iov->end;

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
		 * If addr equals iov_start we just "drop" the
		 * beginning of the IOV. Otherwise, we make the IOV to
		 * end at addr, and add a new IOV start starts at
		 * addr + len.
		 */
		if (addr + len < end) {
			if (addr == start) {
				iov->start += len;
				iov->img_start += len;
			} else {
				if (split_iov(iov, addr + len))
					return -1;
				iov->end = addr;
			}
			break;
		}

		/*
		 * The range spawns beyond the end of the current IOV.
		 * If addr equals iov_start we just "drop" the entire
		 * IOV.  Otherwise, we cut the beginning of the IOV
		 * and continue to the next one with the updated range
		 */
		if (addr == start) {
			list_del(&iov->l);
			xfree(iov);
		} else {
			iov->end = addr;
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

static int drop_iovs(struct lazy_pages_info *lpi, unsigned long addr, int len)
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

	list_for_each_entry_safe(iov, n, iovs, l) {
		if (from >= iov->end)
			continue;

		if (len <= 0 || from + len <= iov->start)
			break;

		if (from < iov->start) {
			len -= (iov->start - from);
			from = iov->start;
		}

		if (from > iov->start) {
			if (split_iov(iov, from))
				return -1;
			list_safe_reset_next(iov, n, l);
			continue;
		}

		if (from + len < iov->end) {
			if (split_iov(iov, from + len))
				return -1;
			list_safe_reset_next(iov, n, l);
		}

		/* here we have iov->start = from, iov->end <= from + len */
		from = iov->end;
		len -= iov->end - iov->start;
		iov->start += off;
		iov->end += off;
		list_move_tail(&iov->l, &remaps);
	}

	merge_iov_lists(&remaps, iovs);

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
			iov->start = start;
			iov->img_start = start;
			iov->end = iov->start + len;
			list_add_tail(&iov->l, &lpi->iovs);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->end)
				break;

			start = vma->end;
		}
	}

	lpi->buf_size = max_iov_len;
	if (posix_memalign(&lpi->buf, PAGE_SIZE, lpi->buf_size))
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
		lp_err(lpi, "Failed to open pagemap\n");
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

static int uffd_check_op_error(struct lazy_pages_info *lpi, const char *op, int *nr_pages, long mcopy_rc)
{
	if (errno == ENOSPC || errno == ESRCH) {
		handle_exit(lpi);
		return 0;
	}

	if (!uffd_recoverable_error(mcopy_rc)) {
		lp_perror(lpi, "%s: mcopy_rc:%ld", op, mcopy_rc);
		return -1;
	}

	lp_debug(lpi, "%s: mcopy_rc:%ld, errno:%d\n", op, mcopy_rc, errno);

	if (mcopy_rc <= 0)
		*nr_pages = 0;
	else
		*nr_pages = mcopy_rc / PAGE_SIZE;

	return 0;
}

static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int *nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = *nr_pages * page_size();

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	if (ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy) &&
	    uffd_check_op_error(lpi, "copy", nr_pages, uffdio_copy.copy))
		return -1;

	lpi->copied_pages += *nr_pages;

	return 0;
}

static int uffd_io_complete(struct page_read *pr, unsigned long img_addr, int nr)
{
	struct lazy_pages_info *lpi;
	unsigned long addr = 0;
	int req_pages, ret;
	struct lazy_iov *req;

	lpi = container_of(pr, struct lazy_pages_info, pr);

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
	return drop_iovs(lpi, addr, nr * PAGE_SIZE);
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	lp_debug(lpi, "zero page at 0x%llx\n", address);
	if (ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage) &&
	    uffd_check_op_error(lpi, "zero", &nr_pages, uffdio_zeropage.zeropage))
		return -1;

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
	unsigned int nr_pages;
	unsigned long len;
	int err;

	iov = pick_next_range(lpi);
	if (!iov)
		return 0;

	len = min(iov->end - iov->start, lpi->xfer_len);

	iov = extract_range(iov, iov->start, iov->start + len);
	if (!iov)
		return -1;
	list_move(&iov->l, &lpi->reqs);

	nr_pages = (iov->end - iov->start) / PAGE_SIZE;

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

	lp_debug(lpi, "%s: %llx(%llx)\n", msg->event == UFFD_EVENT_REMOVE ? "REMOVE" : "UNMAP", unreg.start, unreg.len);

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

	/* Align requested address to the next page boundary */
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_debug(lpi, "#PF at 0x%llx\n", address);

	if (is_page_queued(lpi, address))
		return 0;

	iov = find_iov(lpi, address);
	if (!iov)
		return uffd_zero(lpi, address, 1);

	iov = extract_range(iov, address, address + PAGE_SIZE);
	if (!iov)
		return -1;

	list_move(&iov->l, &lpi->reqs);

	update_xfer_len(lpi, true);

	ret = uffd_handle_pages(lpi, iov->img_start, 1, PR_ASYNC | PR_ASAP);
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

		if (list_empty(&lpis))
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
	if (ret != sizeof(fin))
		pr_perror("Failed sending restore finished indication");

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
		if (connect_to_page_server_to_recv(epollfd)) {
			xfree(events);
			return -1;
		}
	}

	ret = handle_requests(epollfd, &events, nr_fds);

	disconnect_from_page_server();

	xfree(events);
	return ret;
}
