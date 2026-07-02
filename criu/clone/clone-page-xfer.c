/*
 * CLONE page transfer support.
 *
 * This file contains CLONE-specific page transfer functionality including
 * compression statistics, state management, signaling functions, and
 * protocol extensions for CLONE migration.
 */

#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include "clone/clone-page-xfer.h"
#include "xmalloc.h"
#include "page-xfer.h"
#include "page.h"
#include "pstree.h"
#include "cr_options.h"
#include "criu-log.h"
#include "image.h"
#include "pagemap.h"
#include "mem.h"
#include "clone/clone-unified-thread.h"
#include "common/list.h"
#include "common/bug.h"
#include "util.h"

/* Global compression statistics for stats printing (used by clone-bulk-send.c too) */
unsigned long g_compress_uncompressed_bytes = 0;
unsigned long g_compress_compressed_bytes = 0;

/*
 * Wait for all_pages_sent ACK from the target.
 * Called on the source side after sending PS_IOV_ALL_PAGES_SENT.
 */
int wait_for_all_pages_sent_ack(int sk)
{
	struct page_server_iov pi;

	pr_info("Waiting for all_pages_sent ACK from target...\n");
	BUG_ON(page_server_recv(sk, &pi, sizeof(pi), MSG_WAITALL) != sizeof(pi));
	BUG_ON(decode_ps_cmd(pi.cmd) != PS_IOV_ALL_PAGES_SENT_ACK);

	pr_info("Received all_pages_sent ACK from target\n");
	return 0;
}


/*
 * Send "all pages sent" signal to the target (CLONE phased migration).
 * Called on the source side after dirty bitmap transfer completes, so
 * the target knows it can zero-fill any remaining page faults for new
 * VMAs. If sk >= 0, use that socket; otherwise use global page_server_sk.
 */
int send_all_pages_sent_signal(int sk)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_ALL_PAGES_SENT,
		.nr_pages = 0,
		.vaddr = 0,
		.dst_id = 0,
	};
	int use_sk = (sk >= 0) ? sk : get_page_server_sk();

	BUG_ON(use_sk < 0);

	pr_info("Sending all_pages_sent signal to target\n");
	return send_psi(use_sk, &pi);
}

/*
 * Send ACK for all_pages_sent signal (CLONE phased migration).
 * Called on the target side after drain thread finishes, so the source
 * knows it's safe to close the connection.
 */
int send_all_pages_sent_ack(void)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_ALL_PAGES_SENT_ACK,
		.nr_pages = 0,
		.vaddr = 0,
		.dst_id = 0,
	};
	int sk = get_page_server_sk();

	BUG_ON(sk < 0);

	pr_info("Sending all_pages_sent ACK to source\n");
	return send_psi(sk, &pi);
}

int clone_send_skeleton_files(int sk)
{
	DIR *dir;
	struct dirent *de;
	int count = 0;

	dir = opendir(opts.imgs_dir);
	if (!dir) {
		pr_perror("Cannot open images dir %s", opts.imgs_dir);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		struct page_server_iov pi;
		char path[PATH_MAX];
		struct stat st;
		int fd, name_len;
		void *buf;

		if (de->d_name[0] == '.')
			continue;

		name_len = strlen(de->d_name);
		if (name_len < 4 || strcmp(de->d_name + name_len - 4, ".img") != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", opts.imgs_dir, de->d_name);
		if (stat(path, &st) < 0 || st.st_size == 0)
			continue;

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			pr_perror("Cannot open %s", path);
			continue;
		}

		buf = xmalloc(st.st_size);
		if (!buf) {
			close(fd);
			closedir(dir);
			return -1;
		}

		if (read(fd, buf, st.st_size) != st.st_size) {
			pr_perror("Short read on %s", path);
			xfree(buf);
			close(fd);
			closedir(dir);
			return -1;
		}
		close(fd);

		pi.cmd = PS_IOV_SKELETON_FILE;
		pi.nr_pages = name_len;
		pi.vaddr = st.st_size;
		pi.dst_id = 0;

		if (send_psi(sk, &pi) < 0 ||
		    page_server_send(sk, de->d_name, name_len, 0) < 0 ||
		    page_server_send(sk, buf, st.st_size, 0) < 0) {
			pr_err("Failed to send skeleton file %s\n", de->d_name);
			xfree(buf);
			closedir(dir);
			return -1;
		}

		xfree(buf);
		count++;
	}

	closedir(dir);
	pr_info("Sent %d skeleton files to target\n", count);
	return 0;
}

/*
 * Request all pages from the source in batch mode.
 * CLONE-specific: used for bulk page transfer.
 */
int clone_request_all_remote_pages(unsigned long img_id)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET_ALL,
		.nr_pages = 0,  /* Not used in batch mode */
		.vaddr = 0,     /* Not used in batch mode */
		.dst_id = img_id,
	};

	pr_info("Requesting all pages for img_id=%lu in batch mode\n", img_id);
	BUG_ON(send_psi(get_page_server_sk(), &pi));

	page_server_tcp_nodelay(get_page_server_sk(), true);
	return 0;
}

/*
 * Close the page server socket (server-side).
 * Used after sending dirty bitmap in CLONE phased migration.
 */
void clone_close_page_server_socket(void)
{
	int sk = get_page_server_sk();

	if (sk >= 0)
		pr_info("Closing page server socket (server-side)\n");
	/* Also close the listen socket to release the port */
	close_listen_socket();
}

/*
 * clone_write_lazy_vmas_to_pagemap - Write lazy VMA entries to pagemap file
 *
 * Why this is needed:
 *   The uffd page fault handler (collect_iovs in uffd.c) reads the pagemap file
 *   to build a list of address ranges it can serve via userfaultfd. It looks for
 *   entries with the PE_LAZY flag to know which addresses should be handled.
 *
 *   In regular lazy-pages mode, lazy pages go through generate_iovs() and into
 *   the page_pipe, then page_xfer_dump_pages() writes them to pagemap.
 *
 *   In CLONE mode, lazy VMAs skip the page-by-page scan entirely (optimization).
 *   They're collected in global_lazy_vmas list instead. This function writes
 *   those VMAs to the pagemap so collect_iovs() can find them.
 *
 * How it works:
 *   Called from page_xfer_dump_pages() to interleave lazy VMA entries with
 *   regular page entries, maintaining address order in the pagemap file.
 *   Writes all lazy VMAs with start address < before_vaddr.
 *
 * @xfer: Page transfer context
 * @before_vaddr: Write lazy VMAs starting before this address
 * @cur_lve: Current position in lazy VMA list (for iterative calls)
 */
int clone_write_lazy_vmas_to_pagemap(struct page_xfer *xfer, unsigned long before_vaddr,
				     struct lazy_vma_entry **cur_lve)
{
	struct list_head *global_list = clone_mem_get_lazy_vmas();
	struct lazy_vma_entry *lve = *cur_lve;

	/* Start from beginning if not set */
	if (!lve && !list_empty(global_list))
		lve = list_first_entry(global_list, struct lazy_vma_entry, list);

	/*
	 * Write all lazy VMAs that start before before_vaddr.
	 * Use lve->start/end (not lve->vma->e) since vma structs
	 * may be freed after the dump completes.
	 */
	while (lve && &lve->list != global_list) {
		struct iovec iov;
		u32 flags = PE_LAZY;
		unsigned long vma_start = lve->start;

		/*
		 * In server mode, filter VMAs by dst_id (for multi-process dumps).
		 * In local mode, xfer->dst_id is unreliable (union with pmi/pi),
		 * so skip the check. CLONE local mode dumps single process anyway.
		 */
		if (opts.use_page_server && lve->dst_id != xfer->dst_id) {
			lve = list_entry(lve->list.next, struct lazy_vma_entry, list);
			continue;
		}

		/* Stop if this VMA starts at or after our limit */
		if (vma_start >= before_vaddr)
			break;

		iov.iov_base = (void *)(unsigned long)lve->start;
		iov.iov_len = lve->end - lve->start;

		BUG_ON(iov.iov_base < (void *)xfer->offset);
		iov.iov_base -= xfer->offset;

		pr_debug("Writing lazy VMA pagemap: 0x%lx-0x%lx (%lu pages)\n",
			(unsigned long)lve->start, (unsigned long)lve->end,
			(unsigned long)(iov.iov_len / PAGE_SIZE));

		BUG_ON(xfer->write_pagemap(xfer, &iov, flags));

		lve = list_entry(lve->list.next, struct lazy_vma_entry, list);
	}

	*cur_lve = lve;
	return 0;
}

/*
 * Raw send/recv wrappers for P3 parallel sockets.
 * These bypass TLS and use plain TCP for performance.
 * Used by clone-bulk-send.c and clone-p3-receiver.c.
 */
int page_server_send_raw(int sk, const void *buf, size_t sz, int fl)
{
	const char *cursor = buf;
	size_t remaining = sz;

	if (fl & MSG_DONTWAIT)
		return send(sk, buf, sz, fl);

	while (remaining > 0) {
		int ret = send(sk, cursor, remaining, fl);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			return 0;
		cursor += ret;
		remaining -= ret;
	}
	return sz;
}

int page_server_recv_raw(int sk, void *buf, size_t sz, int fl)
{
	return recv(sk, buf, sz, fl);
}

