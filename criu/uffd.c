#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "int.h"
#include "page.h"
#include "include/log.h"
#include "include/criu-plugin.h"
#include "include/pagemap.h"
#include "include/files-reg.h"
#include "include/kerndat.h"
#include "include/mem.h"
#include "include/uffd.h"
#include "include/util-pie.h"
#include "include/protobuf.h"
#include "include/pstree.h"
#include "include/crtools.h"
#include "include/cr_options.h"
#include "xmalloc.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "lazy-pages: "

static int send_uffd(int sendfd, int pid)
{
	int fd;
	int len;
	int ret = -1;
	struct sockaddr_un sun;

	if (!opts.addr) {
		pr_info("Please specify a file name for the unix domain socket\n");
		pr_info("used to communicate between the lazy-pages server\n");
		pr_info("and the restore process. Use the --address option like\n");
		pr_info("criu restore --lazy-pages --address /tmp/userfault.socket\n");
		return -1;
	}

	if (sendfd < 0)
		return -1;

	if (strlen(opts.addr) >= sizeof(sun.sun_path)) {
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, opts.addr);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(opts.addr);
	if (connect(fd, (struct sockaddr *) &sun, len) < 0) {
		pr_perror("connect to %s failed", opts.addr);
		goto out;
	}

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	pr_debug("Sending PID %d\n", pid);
	if (send(fd, &pid, sizeof(pid), 0) < 0) {
		pr_perror("PID sending error:");
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_perror("send_fd error:");
		goto out;
	}
	ret = 0;
out:
	close(fd);
	return ret;
}

/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(struct task_restore_args *task_args, int pid)
{
	struct uffdio_api uffdio_api;
	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

	/*
	 * Check if the UFFD_API is the one which is expected
	 */
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(task_args->uffd, UFFDIO_API, &uffdio_api)) {
		pr_err("Checking for UFFDIO_API failed.\n");
		return -1;
	}
	if (uffdio_api.api != UFFD_API) {
		pr_err("Result of looking up UFFDIO_API does not match: %Lu\n", uffdio_api.api);
		return -1;
	}

	if (send_uffd(task_args->uffd, pid) < 0) {
		close(task_args->uffd);
		return -1;
	}

	return 0;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if (strlen(opts.addr) >= sizeof(saddr->sun_path)) {
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(opts.addr);

	memset(saddr, 0, sizeof(struct sockaddr_un));
	saddr->sun_family = AF_UNIX;
	strcpy(saddr->sun_path, opts.addr);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(opts.addr);

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

static int pid;

static int ud_open()
{
	int client;
	int listen;
	int newfd;
	int ret = -1;
	struct sockaddr_un saddr;
	socklen_t len;

	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *)&saddr, &len)) < 0) {
		pr_perror("server_accept error: %d", client);
		close(listen);
		return -1;
	}

	pr_debug("client fd %d\n", client);

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &pid, sizeof(pid), 0);
	if (ret != sizeof(pid)) {
		pr_perror("PID recv error:");
		ret = -1;
		goto out;
	}
	pr_debug("received PID: %d\n", pid);

	newfd = recv_fd(client);
	if (newfd < 0) {
		pr_perror("recv_fd error:");
		goto out;
	}
	pr_debug("newfd %d\n", newfd);
	close(client);

	return newfd;
out:
	close(listen);
	close(client);
	return ret;
}

static int get_page(unsigned long addr, void *dest)
{
	struct iovec iov;
	int ret;
	unsigned char buf[PAGE_SIZE];
	struct page_read pr;

	ret = open_page_read(pid, &pr, PR_TASK | PR_MOD);
	pr_debug("get_page ret %d\n", ret);

	ret = pr.get_pagemap(&pr, &iov);
	pr_debug("get_pagemap ret %d\n", ret);
	if (ret <= 0)
		return ret;

	ret = pr.seek_page(&pr, addr);
	pr_debug("seek_pagemap_page ret 0x%x\n", ret);
	if (ret <= 0)
		return ret;

	if (pr.pe->zero)
		return 0;

	ret = pr.read_pages(&pr, addr, 1, buf, 0);
	pr_debug("read_pages ret %d\n", ret);
	if (ret <= 0)
		return ret;

	memcpy(dest, buf, PAGE_SIZE);

	if (pr.close)
		pr.close(&pr);

	return 1;
}

#define UFFD_FLAG_SENT	0x1

struct uffd_pages_struct {
	struct list_head list;
	unsigned long addr;
	int flags;
};

static unsigned long total_pages;
static unsigned long uffd_copied_pages;

static int uffd_copy_page(int uffd, __u64 address, void *dest)
{
	struct uffdio_copy uffdio_copy;
	int rc;

	rc = get_page(address, dest);
	if (rc <= 0)
		return -1;

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long) dest;
	uffdio_copy.len = page_size();
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;

	pr_debug("uffdio_copy.dst 0x%llx\n", uffdio_copy.dst);
	rc = ioctl(uffd, UFFDIO_COPY, &uffdio_copy);
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


	return uffdio_copy.copy;

}

static int collect_uffd_pages(struct page_read *pr, struct list_head *uffd_list)
{
	unsigned long base;
	int i;
	struct iovec iov;
	unsigned long nr_pages;
	unsigned long ps;
	int rc;
	struct uffd_pages_struct *uffd_pages;
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(root_item)->vmas;

	rc = pr->get_pagemap(pr, &iov);
	if (rc <= 0)
		return 0;

	ps = page_size();
	nr_pages = iov.iov_len / ps;
	base = (unsigned long) iov.iov_base;
	pr_debug("iov.iov_base 0x%lx (%ld pages)\n", base, nr_pages);

	for (i = 0; i < nr_pages; i++) {
		bool uffd_page = false;
		base = (unsigned long) iov.iov_base + (i * ps);
		/*
		 * Only pages which are MAP_ANONYMOUS and MAP_PRIVATE
		 * are relevant for userfaultfd handling.
		 * Loop over all VMAs to see if the flags matching.
		 */
		list_for_each_entry(vma, &vmas->h, list) {
			/*
			 * This loop assumes that base can actually be found
			 * in the VMA list.
			 */
			if (base >= vma->e->start && base < vma->e->end) {
				if (vma_entry_can_be_lazy(vma->e)) {
					uffd_page = true;
					break;
				}
			}
		}

		/* This is not a page we are looking for. Move along */
		if (!uffd_page)
			continue;

		pr_debug("Adding 0x%lx to our list\n", base);

		uffd_pages = xzalloc(sizeof(struct uffd_pages_struct));
		if (!uffd_pages)
			return -1;
		uffd_pages->addr = base;
		list_add(&uffd_pages->list, uffd_list);
	}

	return 1;
}

static int handle_remaining_pages(int uffd, struct list_head *uffd_list, void *dest)
{
	struct uffd_pages_struct *uffd_pages;
	int rc;

	list_for_each_entry(uffd_pages, uffd_list, list) {
		pr_debug("Checking remaining pages 0x%lx (flags 0x%x)\n",
			 uffd_pages->addr, uffd_pages->flags);
		if (uffd_pages->flags & UFFD_FLAG_SENT)
			continue;

		rc = uffd_copy_page(uffd, uffd_pages->addr, dest);
		if (rc < 0) {
			pr_err("Error during UFFD copy\n");
			return -1;
		}

		uffd_copied_pages++;
		uffd_pages->flags |= UFFD_FLAG_SENT;
	}

	return 0;
}


static int handle_regular_pages(int uffd, struct list_head *uffd_list, void *dest, __u64 address)
{
	int rc;
	struct uffd_pages_struct *uffd_pages;

	rc = uffd_copy_page(uffd, address, dest);
	if (rc < 0) {
		pr_err("Error during UFFD copy\n");
		return -1;
	}

	uffd_copied_pages++;
	/*
	 * Mark this page as having been already transferred, so
	 * that it has not to be copied again later.
	 */
	list_for_each_entry(uffd_pages, uffd_list, list) {
		if (uffd_pages->addr == address)
			uffd_pages->flags |= UFFD_FLAG_SENT;
	}

	return 0;
}

/*
 *  Setting up criu infrastructure and scan for VMAs.
 */
static int find_vmas(struct list_head *uffd_list)
{
	struct cr_img *img;
	int ret;
	struct vm_area_list vmas;
	int vn = 0;
	struct rst_info *ri;
	struct page_read pr;
	struct uffd_pages_struct *uffd_pages;


	if (check_img_inventory() == -1)
		return -1;

	vm_area_list_init(&vmas);

	/* Allocate memory for task_entries */
	if (prepare_task_entries() == -1)
		return -1;

	if (prepare_pstree() == -1)
		return -1;

	ri = rsti(root_item);
	if (!ri)
		return -1;

	img = open_image(CR_FD_MM, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ri->mm, PB_MM);
	close_image(img);
	if (ret == -1)
		return -1;

	pr_debug("Found %zd VMAs in image\n", ri->mm->n_vmas);

	while (vn < ri->mm->n_vmas) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			goto out;

		ret = 0;
		ri->vmas.nr++;
		vma->e = ri->mm->vmas[vn++];

		list_add_tail(&vma->list, &ri->vmas.h);

		if (vma_area_is_private(vma, kdat.task_size)) {
			vmas.priv_size += vma_area_len(vma);
			if (vma->e->flags & MAP_GROWSDOWN)
				vmas.priv_size += PAGE_SIZE;
		}

		pr_info("vma 0x%"PRIx64" 0x%"PRIx64"\n", vma->e->start, vma->e->end);
	}

	ret = open_page_read(pid, &pr, PR_TASK);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}
	/*
	 * This puts all pages which should be handled by userfaultfd
	 * in the list uffd_list. This list is later used to detect if
	 * a page has already been transferred or if it needs to be
	 * pushed into the process using userfaultfd.
	 */
	do {
		ret = collect_uffd_pages(&pr, uffd_list);
		if (ret == -1) {
			goto out;
		}
	} while (ret);

	if (pr.close)
		pr.close(&pr);

	/* Count detected pages */
	list_for_each_entry(uffd_pages, uffd_list, list)
	    ret++;

	pr_debug("Found %d pages to be handled by UFFD\n", ret);

out:
	return ret;
}

static int handle_requests(int fd)
{
	fd_set set;
	int ret = -1;
	struct uffd_msg msg;
	__u64 flags;
	__u64 address;
	unsigned long ps;
	struct timeval timeout;
	struct uffd_pages_struct *uffd_pages;
	void *dest;

	LIST_HEAD(uffd_list);

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	if ((total_pages = find_vmas(&uffd_list)) == -1)
		return -1;

	/* Initialize FD sets for read() with timeouts (using select()) */
	FD_ZERO(&set);
	FD_SET(fd, &set);

	/* All operations will be done on page size */
	ps = page_size();
	dest = xmalloc(ps);
	if (!dest)
		return ret;

	while (1) {
		bool page_sent = false;
		/*
		 * Setting the timeout to 5 seconds. If after this time
		 * no uffd pages are requested the code switches to
		 * copying the remaining pages.
		 *
		 * Timeout is re-defined every time select() is run as
		 * select(2) says:
		 *  Consider timeout to be undefined after select() returns.
		 */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		ret = select(fd + 1, &set, NULL, NULL, &timeout);
		pr_debug("select() rc: 0x%x\n", ret);
		if (ret == 0) {
			pr_debug("read timeout\n");
			pr_debug("switching from request to copy mode\n");
			break;
		}
		ret = read(fd, &msg, sizeof(msg));
		pr_debug("read() ret: 0x%x\n", ret);
		if (!ret)
			break;

		if (ret != sizeof(msg)) {
			pr_perror("Can't read userfaultfd message from socket");
			ret = -1;
			break;
		}

		ret = 0;
		/* Align requested address to the next page boundary */
		address = msg.arg.pagefault.address & ~(ps - 1);
		pr_debug("msg.arg.pagefault.address 0x%llx\n", address);

		/* Make sure to not transfer a page twice */
		list_for_each_entry(uffd_pages, &uffd_list, list) {
			if ((uffd_pages->addr == address) && (uffd_pages->flags & UFFD_FLAG_SENT)) {
				page_sent = true;
				break;
			}
		}

		if (page_sent)
			continue;

		/* Now handle the pages actually requested. */

		flags = msg.arg.pagefault.flags;
		pr_debug("msg.arg.pagefault.flags 0x%llx\n", flags);

		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			pr_err("unexpected msg event %u\n", msg.event);
			ret = -1;
			goto out;
		}

		ret = handle_regular_pages(fd, &uffd_list, dest, address);
		if (ret < 0) {
			pr_err("Error during regular page copy\n");
			ret = -1;
			goto out;
		}
	}
	pr_debug("Handle remaining pages\n");
	ret = handle_remaining_pages(fd, &uffd_list, dest);
	if (ret < 0) {
		pr_err("Error during remaining page copy\n");
		ret = 1;
		goto out;
	}

	pr_debug("With UFFD transferred pages: (%ld/%ld)\n", uffd_copied_pages, total_pages);
	if ((uffd_copied_pages != total_pages) && (total_pages > 0)) {
		pr_warn("Only %ld of %ld pages transferred via UFFD\n", uffd_copied_pages,
			total_pages);
		pr_warn("Something probably went wrong.\n");
		ret = 1;
		goto out;
	}
	ret = 0;

out:
	free(dest);
	close(fd);
	return ret;

}
int uffd_listen()
{
	int uffd;
	int uffd_flags;

	LIST_HEAD(uffd_list);

	if (!opts.addr) {
		pr_info("Please specify a file name for the unix domain socket\n");
		pr_info("used to communicate between the lazy-pages server\n");
		pr_info("and the restore process. Use the --address option like\n");
		pr_info("criu --lazy-pages --address /tmp/userfault.socket\n");
		return -1;
	}

	pr_debug("Waiting for incoming connections on %s\n", opts.addr);
	if ((uffd = ud_open()) < 0)
		exit(0);

	pr_debug("uffd is 0x%d\n", uffd);
	uffd_flags = fcntl(uffd, F_GETFD, NULL);
	pr_debug("uffd_flags are 0x%x\n", uffd_flags);

	return handle_requests(uffd);
}
