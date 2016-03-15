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
#define UFFD_FLAG_VDSO	0x2

struct uffd_pages_struct {
	struct list_head list;
	unsigned long addr;
	int flags;
};

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

static int collect_uffd_pages(struct page_read *pr, struct list_head *uffd_list,
			      unsigned long *vma_size)
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
		bool uffd_vdso = false;
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
				if ((vma->e->flags & MAP_ANONYMOUS) &&
				    (vma->e->flags & MAP_PRIVATE) &&
				    !(vma_area_is(vma, VMA_AREA_VSYSCALL))) {
					uffd_page = true;
					if (vma_area_is(vma, VMA_AREA_VDSO))
						uffd_vdso = true;
					break;
				}
			}
		}

		/* This is not a page we are looking for. Move along */
		if (!uffd_page)
			continue;

		pr_debug("Adding 0x%lx to our list\n", base);

		*vma_size += ps;
		uffd_pages = xzalloc(sizeof(struct uffd_pages_struct));
		if (!uffd_pages)
			return -1;
		uffd_pages->addr = base;
		if (uffd_vdso)
			uffd_pages->flags |= UFFD_FLAG_VDSO;
		list_add(&uffd_pages->list, uffd_list);
	}

	return 1;
}

static int handle_remaining_pages(int uffd, struct list_head *uffd_list, unsigned long *vma_size,
				  void *dest)
{
	unsigned long uffd_copied_pages = 0;
	struct uffd_pages_struct *uffd_pages;
	int rc;

	pr_debug("remaining vma_size: 0x%lx\n", *vma_size);
	pr_debug("uffd_copied_pages:    %ld\n", uffd_copied_pages);

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
		*vma_size -= rc;

		pr_debug("remaining vma_size: 0x%lx\n", *vma_size);
		uffd_copied_pages++;
		uffd_pages->flags |= UFFD_FLAG_SENT;
	}

	return uffd_copied_pages;
}


static int handle_regular_pages(int uffd, struct list_head *uffd_list, unsigned long *vma_size,
				void *dest, __u64 address)
{
	int rc;
	struct uffd_pages_struct *uffd_pages;

	rc = uffd_copy_page(uffd, address, dest);
	if (rc < 0) {
		pr_err("Error during UFFD copy\n");
		return -1;
	}
	*vma_size -= rc;

	/*
	 * Mark this page as having been already transferred, so
	 * that it has not to be copied again later.
	 */
	list_for_each_entry(uffd_pages, uffd_list, list) {
		if (uffd_pages->addr == address)
			uffd_pages->flags |= UFFD_FLAG_SENT;
	}


	return 1;
}

static int handle_vdso_pages(int uffd, struct list_head *uffd_list, unsigned long *vma_size,
			     void *dest)
{
	int rc;
	struct uffd_pages_struct *uffd_pages;
	int uffd_copied_pages = 0;

	list_for_each_entry(uffd_pages, uffd_list, list) {
		if (!(uffd_pages->flags & UFFD_FLAG_VDSO))
			continue;
		rc = uffd_copy_page(uffd, uffd_pages->addr, dest);
		if (rc < 0) {
			pr_err("Error during UFFD copy\n");
			return -1;
		}
		*vma_size -= rc;
		uffd_copied_pages++;
		uffd_pages->flags |= UFFD_FLAG_SENT;
	}
	return uffd_copied_pages;
}

/*
 *  Setting up criu infrastructure to easily
 *  access the dump results.
 */
static void criu_init()
{
	/* TODO: return code checking */
	check_img_inventory();
	prepare_task_entries();
	prepare_pstree();
	collect_remaps_and_regfiles();
	prepare_shared_reg_files();
	prepare_mm_pid(root_item);
}

int uffd_listen()
{
	__u64 address;
	void *dest;
	__u64 flags;
	struct uffd_msg msg;
	struct page_read pr;
	unsigned long ps;
	int rc;
	fd_set set;
	struct timeval timeout;
	int uffd;
	unsigned long uffd_copied_pages = 0;
	unsigned long total_pages = 0;
	int uffd_flags;
	struct uffd_pages_struct *uffd_pages;
	bool vdso_sent = false;
	unsigned long vma_size = 0;

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

	/* Setting up criu infrastructure to easily access the dump results */
	criu_init();

	/* Initialize FD sets for read() with timeouts (using select()) */
	FD_ZERO(&set);
	FD_SET(uffd, &set);

	/* All operations will be done on page size */
	ps = page_size();
	dest = xmalloc(ps);
	if (!dest)
		goto out;

	rc = open_page_read(pid, &pr, PR_TASK);
	if (rc <= 0) {
		rc = 1;
		goto out;
	}
	/*
	 * This puts all pages which should be handled by userfaultfd
	 * in the list uffd_list. This list is later used to detect if
	 * a page has already been transferred or if it needs to be
	 * pushed into the process using userfaultfd.
	 */
	do {
		rc = collect_uffd_pages(&pr, &uffd_list, &vma_size);
		if (rc == -1) {
			rc = 1;
			goto out;
		}
	} while (rc);

	if (pr.close)
		pr.close(&pr);


	/* Count detected pages */
	list_for_each_entry(uffd_pages, &uffd_list, list)
	    total_pages++;

	pr_debug("Found %ld pages to be handled by UFFD\n", total_pages);

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
		rc = select(uffd + 1, &set, NULL, NULL, &timeout);
		pr_debug("select() rc: 0x%x\n", rc);
		if (rc == 0) {
			pr_debug("read timeout\n");
			pr_debug("switching from request to copy mode\n");
			break;
		}
		rc = read(uffd, &msg, sizeof(msg));
		pr_debug("read() rc: 0x%x\n", rc);

		if (rc != sizeof(msg)) {
			if (rc < 0)
				pr_perror("read error");
			else
				pr_debug("short read\n");
			continue;
		}

		/* Align requested address to the next page boundary */
		address = msg.arg.pagefault.address & ~(ps - 1);
		pr_debug("msg.arg.pagefault.address 0x%llx\n", address);

		/*
		 * At this point the process on the other side waits for the first page.
		 * In the first step we will force the vdso pages into the new process.
		 */
		if (!vdso_sent) {
			pr_debug("Pushing VDSO pages once\n");
			rc = handle_vdso_pages(uffd, &uffd_list, &vma_size, dest);
			if (rc < 0) {
				pr_err("Error during VDSO handling\n");
				rc = 1;
				goto out;
			}
			uffd_copied_pages += rc;
			vdso_sent = true;
		}

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
			rc = 1;
			goto out;
		}

		rc = handle_regular_pages(uffd, &uffd_list, &vma_size, dest, address);
		if (rc < 0) {
			pr_err("Error during regular page copy\n");
			rc = 1;
			goto out;
		}

		uffd_copied_pages += rc;

	}
	pr_debug("Handle remaining pages\n");
	rc = handle_remaining_pages(uffd, &uffd_list, &vma_size, dest);
	if (rc < 0) {
		pr_err("Error during remaining page copy\n");
		rc = 1;
		goto out;
	}

	uffd_copied_pages += rc;
	pr_debug("With UFFD transferred pages: (%ld/%ld)\n", uffd_copied_pages, total_pages);
	if (uffd_copied_pages != total_pages) {
		pr_warn("Only %ld of %ld pages transferred via UFFD\n", uffd_copied_pages,
			total_pages);
		pr_warn("Something probably went wrong.\n");
		rc = 1;
		goto out;
	}
	rc = 0;

out:
	free(dest);
	close(uffd);
	return rc;
}
