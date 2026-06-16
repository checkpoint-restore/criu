/*
 * CLONE control message receiver (target side).
 *
 * All page data is transferred via P3 receiver threads. This module
 * only handles control messages on the main page server socket:
 * - PS_IOV_ALL_PAGES_SENT signal (source done sending pages)
 */

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "types.h"
#include "criu-log.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "page-xfer.h"
#include "clone/clone-page-xfer.h"
#include "clone/clone-bulk-recv.h"
#include "clone/clone-uffd.h"
#include "uffd.h"
#include "common/bug.h"

#undef LOG_PREFIX
#define LOG_PREFIX "clone-bulk-recv: "

static int clone_recv_skeleton_file(struct page_server_iov *pi)
{
	char filename[128];
	char path[PATH_MAX];
	void *buf;
	int sk = get_page_server_sk();
	int fd, name_len;
	u64 file_size;

	name_len = pi->nr_pages;
	file_size = pi->vaddr;

	if (name_len >= (int)sizeof(filename)) {
		pr_err("Filename too long: %d\n", name_len);
		return -1;
	}

	if (page_server_recv(sk, filename, name_len, MSG_WAITALL) != name_len) {
		pr_err("clone_recv_skeleton_file: failed to recv filename (name_len=%d, errno=%d)\n",
		       name_len, errno);
		return -1;
	}
	filename[name_len] = '\0';

	snprintf(path, sizeof(path), "%s/%s", opts.imgs_dir, filename);

	buf = xmalloc(file_size);
	if (!buf)
		return -1;

	if (page_server_recv(sk, buf, file_size, MSG_WAITALL) != (int)file_size) {
		pr_err("clone_recv_skeleton_file: failed to recv file data '%s' (file_size=%lu, errno=%d)\n",
		       filename, (unsigned long)file_size, errno);
		xfree(buf);
		return -1;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Cannot create %s", path);
		xfree(buf);
		return -1;
	}
	if (write(fd, buf, file_size) != (ssize_t)file_size) {
		pr_perror("Short write to %s", path);
		close(fd);
		xfree(buf);
		return -1;
	}
	close(fd);
	xfree(buf);
	return 0;
}

/* Bulk stream return codes (local defines) */
#define BULK_STREAM_WOULD_BLOCK 0
#define BULK_STREAM_PROGRESS    1
#define BULK_STREAM_COMPLETE    2

/*
 * Async read state for control message processing on the main socket.
 */
struct ps_async_read_bulk {
	unsigned long rb;      /* Bytes read of current header */
	struct page_server_iov pi;
	struct list_head l;
};

static LIST_HEAD(bulk_async_reads);

/*
 * Helper: recv with EAGAIN/EINTR handling for non-blocking reads.
 * Returns bytes received on success, -EAGAIN on would-block, -1 on error.
 */
static int bulk_recv(void *buf, int need, int flags)
{
	int sk = get_page_server_sk();
	int ret;

	ret = page_server_recv(sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR))
			return -EAGAIN;
		pr_err("bulk_recv: page_server_recv returned %d, errno=%d (%s), sk=%d, need=%d, flags=0x%x\n",
		       ret, errno, strerror(errno), sk, need, flags);
		return -1;
	}
	if (ret == 0) {
		pr_err("bulk_recv: page_server_recv returned 0 (EOF), sk=%d, need=%d\n",
		       sk, need);
	}

	return ret;
}

/*
 * Read control message header from main socket.
 * Only PS_IOV_ALL_PAGES_SENT is expected on this socket.
 * Page data on this socket is a bug — all data goes via P3 threads.
 */
static int read_bulk_header(struct ps_async_read_bulk *ar, int flags)
{
	int ret;
	u32 cmd;

	if (ar->rb < sizeof(ar->pi)) {
		void *buf = ((void *)&ar->pi) + ar->rb;
		int need = sizeof(ar->pi) - ar->rb;

		ret = bulk_recv(buf, need, flags);
		if (ret == -EAGAIN)
			return BULK_STREAM_WOULD_BLOCK;
		if (ret < 0) {
			pr_perror("Error reading header from page server");
			return -1;
		}
		ar->rb += ret;
	}

	if (ar->rb < sizeof(ar->pi))
		return BULK_STREAM_PROGRESS;

	/* Header complete — reset for next header */
	ar->rb = 0;
	cmd = decode_ps_cmd(ar->pi.cmd);

	if (cmd == PS_IOV_SKELETON_FILE) {
		pr_debug("read_bulk_header: SKELETON_FILE nr_pages(name_len)=%lu vaddr(file_size)=%lu\n",
			 (unsigned long)ar->pi.nr_pages, (unsigned long)ar->pi.vaddr);
		if (clone_recv_skeleton_file(&ar->pi) < 0) {
			pr_err("read_bulk_header: clone_recv_skeleton_file FAILED\n");
			return -1;
		}
		return BULK_STREAM_PROGRESS;
	}

	if (cmd == PS_IOV_ALL_PAGES_SENT) {
		/* Source signals all pages sent; remaining pages can be zero-filled. */
		pr_debug("All pages sent signal received\n");
		clone_set_all_pages_sent_received();
		/*
		 * Return COMPLETE to stop reading - source is waiting for ACK.
		 * The main loop will check clone_handle_exit() and send the ACK.
		 */
		return BULK_STREAM_COMPLETE;
	}

	/*
	 * Unexpected page data on main socket. All page data should go
	 * through P3 receiver threads. Log details for debugging.
	 */
	pr_err("BUG: page data arrived on main socket!\n");
	pr_err("  cmd=%u nr_pages=%lu vaddr=0x%lx dst_id=%lu\n",
	       cmd, (unsigned long)ar->pi.nr_pages,
	       (unsigned long)ar->pi.vaddr,
	       (unsigned long)ar->pi.dst_id);
	pr_err("  all_pages_sent=%d\n",
	       clone_is_all_pages_sent_received());
	BUG();
	return -1; /* unreachable */
}

int page_server_async_read_bulk(struct epoll_rfd *f)
{
	struct ps_async_read_bulk *ar;
	int ret;

	if (list_empty(&bulk_async_reads)) {

		pr_err("Bulk async read with empty queue\n");
		BUG();
	}

	ar = list_first_entry(&bulk_async_reads, struct ps_async_read_bulk, l);
	ret = read_bulk_header(ar, MSG_DONTWAIT);

	if (ret == BULK_STREAM_COMPLETE) {
		/* End marker - cleanup stream reader */
		list_del(&ar->l);
		xfree(ar);
		/* Only break epoll loop for all_pages_sent - other COMPLETE cases continue */
		if (clone_is_all_pages_sent_received()) {
			pr_info("page_server_async_read_bulk: BULK_STREAM_COMPLETE + all_pages_sent, returning 1 to break epoll\n");
			return 1;
		}
		pr_info("page_server_async_read_bulk: BULK_STREAM_COMPLETE, returning 0\n");
		return 0;
	}
	if (ret < 0) {
		pr_err("page_server_async_read_bulk: bulk_stream returned %d\n", ret);
		return -1;
	}

	/* ret == BULK_STREAM_WOULD_BLOCK or BULK_STREAM_PROGRESS - keep going */
	return 0;
}

int page_server_start_async_read_bulk(void)
{
	struct ps_async_read_bulk *ar;

	/* Only create reader once - it processes the continuous control stream */
	if (!list_empty(&bulk_async_reads))
		return 0;

	ar = xmalloc(sizeof(*ar));
	BUG_ON(!ar);

	ar->rb = 0;
	list_add_tail(&ar->l, &bulk_async_reads);
	return 0;
}

/*
 * Cleanup async bulk reader state.
 * Called when closing the page server socket to prevent stale fd reads.
 */
void page_server_cleanup_async_bulk(void)
{
	struct ps_async_read_bulk *ar, *tmp;

	list_for_each_entry_safe(ar, tmp, &bulk_async_reads, l) {
		list_del(&ar->l);
		xfree(ar);
	}
	pr_debug("Cleaned up async bulk reader state\n");
}
