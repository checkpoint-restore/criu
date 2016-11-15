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
#include <sys/epoll.h>
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

#undef  LOG_PREFIX
#define LOG_PREFIX "lazy-pages: "

#define LAZY_PAGES_SOCK_NAME	"lazy-pages.socket"

static mutex_t *lazy_sock_mutex;

struct lazy_iovec {
	struct list_head l;
	unsigned long base;
	unsigned long len;
};

struct lazy_pages_fd {
	int fd;
	int (*event)(struct lazy_pages_fd *);
};

struct lazy_pages_info {
	int pid;

	struct list_head iovs;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct lazy_pages_fd lpfd;

	struct list_head l;

	void *buf;
};

static LIST_HEAD(lpis);
static int handle_user_fault(struct lazy_pages_fd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_LIST_HEAD(&lpi->l);
	lpi->lpfd.event = handle_user_fault;

	return lpi;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *p, *n;

	if (!lpi)
		return;
	free(lpi->buf);
	list_for_each_entry_safe(p, n, &lpi->iovs, l)
		xfree(p);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->pr.close)
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

	/* for a zombie process pid will be -1 */
	if (pid == -1) {
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

/* Runtime detection if userfaultfd can be used */

static int check_for_uffd()
{
	int uffd;

	uffd = syscall(SYS_userfaultfd, 0);
	/*
	 * uffd == -1 is probably enough to not use lazy-restore
	 * on this system. Additionally checking for ENOSYS
	 * makes sure it is actually not implemented.
	 */
	if ((uffd == -1) && (errno == ENOSYS)) {
		pr_err("Runtime detection of userfaultfd failed on this system.\n");
		pr_err("Processes cannot be lazy-restored on this system.\n");
		return -1;
	}
	close(uffd);
	return 0;
}

int lazy_pages_setup_zombie(void)
{
	if (!opts.lazy_pages)
		return 0;

	if (send_uffd(0, -1))
		return -1;

	return 0;
}

/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(int pid, struct task_restore_args *task_args)
{
	struct uffdio_api uffdio_api;

	if (!opts.lazy_pages) {
		task_args->uffd = -1;
		return 0;
	}

	if (check_for_uffd())
		return -1;
	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (task_args->uffd < 0) {
		pr_perror("Unable to open an userfaultfd descriptor");
		return -1;
	}

	/*
	 * Check if the UFFD_API is the one which is expected
	 */
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(task_args->uffd, UFFDIO_API, &uffdio_api)) {
		pr_err("Checking for UFFDIO_API failed.\n");
		goto err;
	}
	if (uffdio_api.api != UFFD_API) {
		pr_err("Result of looking up UFFDIO_API does not match: %Lu\n", uffdio_api.api);
		goto err;
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
	pr_debug("Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static int update_lazy_iovecs(struct lazy_pages_info *lpi, unsigned long addr,
			      int len)
{
	struct lazy_iovec *lazy_iov, *n;

	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l) {
		unsigned long start = lazy_iov->base;
		unsigned long end = start + lazy_iov->len;

		if (len <= 0)
			break;

		if (addr < start || addr >= end)
			continue;

		if (addr + len < end) {
			if (addr == start) {
				lazy_iov->base += len;
				lazy_iov->len -= len;
			} else {
				struct lazy_iovec *new_iov;

				lazy_iov->len -= (end - addr);

				new_iov = xzalloc(sizeof(*new_iov));
				if (!new_iov)
					return -1;

				new_iov->base = addr + len;
				new_iov->len = end - (addr + len);

				list_add(&new_iov->l, &lazy_iov->l);
			}
			break;
		}

		if (addr == start) {
			list_del(&lazy_iov->l);
			xfree(lazy_iov);
		} else {
			lazy_iov->len -= (end - addr);
		}

		len -= (end - addr);
		addr = end;
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
static int collect_lazy_iovecs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iovec *lazy_iov, *n;
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

			lazy_iov = xzalloc(sizeof(*lazy_iov));
			if (!lazy_iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			lazy_iov->base = start;
			lazy_iov->len = len;
			list_add_tail(&lazy_iov->l, &lpi->iovs);

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
	list_for_each_entry_safe(lazy_iov, n, &lpi->iovs, l)
		xfree(lazy_iov);
free_mm:
	mm_entry__free_unpacked(mm, NULL);

	return ret;
}

static int ud_open(int client, struct lazy_pages_info **_lpi)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int uffd_flags;

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
	pr_debug("received PID: %d\n", lpi->pid);

	if (lpi->pid == -1) {
		lpi_fini(lpi);
		return 0;
	}

	lpi->lpfd.fd = recv_fd(client);
	if (lpi->lpfd.fd < 0) {
		pr_err("recv_fd error");
		goto out;
	}
	pr_debug("lpi->uffd %d\n", lpi->lpfd.fd);

	pr_debug("uffd is 0x%d\n", lpi->lpfd.fd);
	uffd_flags = fcntl(lpi->lpfd.fd, F_GETFD, NULL);
	pr_debug("uffd_flags are 0x%x\n", uffd_flags);

	ret = open_page_read(lpi->pid, &lpi->pr, PR_TASK);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	ret = collect_lazy_iovecs(lpi);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	pr_debug("Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	list_add_tail(&lpi->l, &lpis);
	*_lpi = lpi;

	return 0;

out:
	lpi_fini(lpi);
	return -1;
}

static int uffd_copy_page(struct lazy_pages_info *lpi, __u64 address)
{
	struct uffdio_copy uffdio_copy;
	int rc;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = page_size();
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	pr_debug("uffdio_copy.dst 0x%llx\n", uffdio_copy.dst);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy);
	pr_debug("ioctl UFFDIO_COPY rc 0x%x\n", rc);
	pr_debug("uffdio_copy.copy 0x%llx\n", uffdio_copy.copy);
	if (rc) {
		/* real retval in ufdio_copy.copy */
		if (uffdio_copy.copy != -EEXIST) {
			pr_err("UFFDIO_COPY error %Ld\n", uffdio_copy.copy);
			return -1;
		}
	} else if (uffdio_copy.copy != page_size()) {
		pr_err("UFFDIO_COPY unexpected size %Ld\n", uffdio_copy.copy);
		return -1;
	}

	lpi->copied_pages++;

	return uffdio_copy.copy;

}

static int uffd_zero_page(struct lazy_pages_info *lpi, __u64 address)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long ps = page_size();
	int rc;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = ps;
	uffdio_zeropage.mode = 0;

	pr_debug("uffdio_zeropage.range.start 0x%llx\n", uffdio_zeropage.range.start);
	rc = ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
	pr_debug("ioctl UFFDIO_ZEROPAGE rc 0x%x\n", rc);
	pr_debug("uffdio_zeropage.zeropage 0x%llx\n", uffdio_zeropage.zeropage);
	if (rc) {
		pr_err("UFFDIO_ZEROPAGE error %d\n", rc);
		return -1;
	}

	return ps;
}

static int uffd_handle_page(struct lazy_pages_info *lpi, __u64 address)
{
	int ret;

	lpi->pr.reset(&lpi->pr);

	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret)
		return 0;

	if (pagemap_zero(lpi->pr.pe))
		return uffd_zero_page(lpi, address);

	if (opts.use_page_server)
		ret = get_remote_pages(lpi->pid, address, 1, lpi->buf);
	else
		ret = lpi->pr.read_pages(&lpi->pr, address, 1, lpi->buf, 0);

	if (ret <= 0) {
		pr_err("%d: failed reading pages at %llx\n", lpi->pid, address);
		return ret;
	}

	return uffd_copy_page(lpi, address);
}

static int handle_remaining_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iovec *lazy_iov;
	int nr_pages, i, err;
	unsigned long addr;

	lpi->pr.reset(&lpi->pr);

	list_for_each_entry(lazy_iov, &lpi->iovs, l) {
		nr_pages = lazy_iov->len / PAGE_SIZE;

		for (i = 0; i < nr_pages; i++) {
			addr = lazy_iov->base + i * PAGE_SIZE;

			err = uffd_handle_page(lpi, addr);
			if (err < 0) {
				pr_err("Error during UFFD copy\n");
				return -1;
			}
		}
	}

	return 0;
}

static int handle_regular_pages(struct lazy_pages_info *lpi, __u64 address)
{
	int rc;

	rc = uffd_handle_page(lpi, address);
	if (rc < 0) {
		pr_err("Error during UFFD copy\n");
		return -1;
	}

	rc = update_lazy_iovecs(lpi, address, PAGE_SIZE);
	if (rc < 0)
		return -1;

	return 0;
}

static int handle_user_fault(struct lazy_pages_fd *lpfd)
{
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	__u64 flags;
	__u64 address;
	int ret;

	lpi = container_of(lpfd, struct lazy_pages_info, lpfd);

	ret = read(lpfd->fd, &msg, sizeof(msg));
	pr_debug("read() ret: 0x%x\n", ret);
	if (!ret)
		return 1;

	if (ret != sizeof(msg)) {
		if (ret < 0)
			pr_perror("Can't read userfaultfd message");
		else
			pr_err("Can't read userfaultfd message: short read");
		return -1;
	}

	if (msg.event != UFFD_EVENT_PAGEFAULT) {
		pr_err("unexpected msg event %u\n", msg.event);
		return -1;
	}

	/* Align requested address to the next page boundary */
	address = msg.arg.pagefault.address & ~(page_size() - 1);
	pr_debug("msg.arg.pagefault.address 0x%llx\n", address);

	/* Now handle the pages actually requested. */
	flags = msg.arg.pagefault.flags;
	pr_debug("msg.arg.pagefault.flags 0x%llx\n", flags);

	ret = handle_regular_pages(lpi, address);
	if (ret < 0) {
		pr_err("Error during regular page copy\n");
		return -1;
	}

	return 0;
}

static int lazy_pages_summary(struct lazy_pages_info *lpi)
{
	pr_debug("Process %d: with UFFD transferred pages: (%ld/%ld)\n",
		 lpi->pid, lpi->copied_pages, lpi->total_pages);

	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		pr_warn("Only %ld of %ld pages transferred via UFFD\n", lpi->copied_pages,
			lpi->total_pages);
		pr_warn("Something probably went wrong.\n");
		return 1;
	}

	return 0;
}

#define POLL_TIMEOUT 5000

static int handle_requests(int epollfd, struct epoll_event *events)
{
	int nr_fds = task_entries->nr_tasks;
	struct lazy_pages_info *lpi;
	int ret = -1;
	int i;

	while (1) {
		struct lazy_pages_fd *lpfd;

		/*
		 * Setting the timeout to 5 seconds. If after this time
		 * no uffd pages are requested the code switches to
		 * copying the remaining pages.
		 */
		ret = epoll_wait(epollfd, events, nr_fds, POLL_TIMEOUT);
		pr_debug("epoll() ret: 0x%x\n", ret);
		if (ret < 0) {
			pr_perror("polling failed");
			goto out;
		} else if (ret == 0) {
			pr_debug("read timeout\n");
			pr_debug("switching from request to copy mode\n");
			break;
		}

		for (i = 0; i < ret; i++) {
			int err;

			lpfd = (struct lazy_pages_fd *)events[i].data.ptr;
			err = lpfd->event(lpfd);
			if (err < 0)
				goto out;
		}
	}
	pr_debug("Handle remaining pages\n");
	list_for_each_entry(lpi, &lpis, l) {
		ret = handle_remaining_pages(lpi);
		if (ret < 0) {
			pr_err("Error during remaining page copy\n");
			ret = 1;
			goto out;
		}
	}

	list_for_each_entry(lpi, &lpis, l)
		ret += lazy_pages_summary(lpi);

out:
	return ret;

}

static int lazy_pages_prepare_pstree(void)
{
	if (check_img_inventory() == -1)
		return -1;

	/* Allocate memory for task_entries */
	if (prepare_task_entries() == -1)
		return -1;

	if (prepare_pstree() == -1)
		return -1;

	return 0;
}

static int prepare_epoll(int nr_fds, struct epoll_event **events)
{
	int epollfd;

	*events = xmalloc(sizeof(struct epoll_event) * nr_fds);
	if (!*events)
		return -1;

	epollfd = epoll_create(nr_fds);
	if (epollfd == -1) {
		pr_perror("epoll_create failed");
		goto free_events;
	}

	return epollfd;

free_events:
	free(*events);
	return -1;
}

static int epoll_add_lpfd(int epollfd, struct lazy_pages_fd *lpfd)
{
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.ptr = lpfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, lpfd->fd, &ev) == -1) {
		pr_perror("epoll_ctl failed");
		return -1;
	}

	return 0;
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
	pr_debug("client fd %d\n", client);

	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi = NULL;
		if (ud_open(client, &lpi))
			goto close_uffd;
		if (lpi == NULL)
			continue;
		if (epoll_add_lpfd(epollfd, &lpi->lpfd))
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
	int epollfd;
	int lazy_sk;
	int ret;

	if (check_for_uffd())
		return -1;

	if (lazy_pages_prepare_pstree())
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

	epollfd = prepare_epoll(task_entries->nr_tasks, &events);
	if (epollfd < 0)
		return -1;

	if (prepare_uffds(lazy_sk, epollfd))
		return -1;

	if (connect_to_page_server())
		return -1;

	ret = handle_requests(epollfd, events);

	return ret;
}
