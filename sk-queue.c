#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

#include "types.h"
#include "list.h"
#include "image.h"
#include "crtools.h"
#include "util.h"
#include "util-net.h"

#include "sk-queue.h"

static LIST_HEAD(packets_list);

int read_sk_queues(void)
{
	struct sk_packet *pkt;
	int ret, fd;

	pr_info("Trying to read socket queues image\n");

	fd = open_image_ro(CR_FD_SK_QUEUES);
	if (fd < 0)
		return -1;

	while (1) {
		struct sk_packet_entry tmp;

		pkt = xmalloc(sizeof(*pkt));
		if (!pkt) {
			pr_err("Failed to allocate packet header\n");
			return -ENOMEM;
		}
		ret = read_img_eof(fd, &pkt->entry);
		if (ret <= 0)
			break;

		pkt->img_off = lseek(fd, 0, SEEK_CUR);
		/*
		 * NOTE: packet must be added to the tail. Otherwise sequence
		 * will be broken.
		 */
		list_add_tail(&pkt->list, &packets_list);
		lseek(fd, pkt->entry.length, SEEK_CUR);
	}
	close(fd);
	xfree(pkt);

	return ret;
}

int dump_sk_queue(int sock_fd, int sock_id)
{
	struct sk_packet_entry *pe;
	unsigned long size;
	socklen_t tmp;
	int ret, orig_peek_off;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;
	/*
	 * Try to alloc buffer for max supported DGRAM + our header.
	 * Note: STREAM queue will be written by chunks of this size.
	 */
	pe = xmalloc(size + sizeof(struct sk_packet_entry));
	if (!pe)
		return -ENOMEM;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail\n");
		goto err_brk;
	}

	pe->id_for = sock_id;

	while (1) {
		struct iovec iov = {
			.iov_base	= pe->data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};

		ret = pe->length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (ret < 0) {
			if (ret == -EAGAIN)
				break; /* we're done */
			pr_perror("sys_recvmsg fail: error\n");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM thuncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}
		ret = write_img_buf(fdset_fd(glob_fdset, CR_FD_SK_QUEUES),
				pe, sizeof(pe) + pe->length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original peek offset.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int));
	if (ret < 0)
		pr_perror("setsockopt failed on restore\n");
err_brk:
	xfree(pe);
	return ret;
}

void show_sk_queues(int fd, struct cr_options *o)
{
	struct sk_packet_entry pe;
	char *buf = NULL, *p;
	int ret;

	pr_img_head(CR_FD_SK_QUEUES);
	while (1) {
		ret = read_img_eof(fd, &pe);
		if (ret <= 0)
			break;
		p = xrealloc(buf, pe.length);
		if (!p)
			break;
		buf = p;
		pr_info("pkt for %u length %u bytes\n",
				pe.id_for, pe.length);

		ret = read_img_buf(fd, (unsigned char *)buf, pe.length);
		if (ret < 0)
			break;

		print_data(0, (unsigned char *)buf, pe.length);
	}
	xfree(buf);
	pr_img_tail(CR_FD_SK_QUEUES);
}

int restore_sk_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret, img_fd;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	img_fd = open_image_ro(CR_FD_SK_QUEUES);
	if (img_fd < 0)
		return -1;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		struct sk_packet_entry *entry = &pkt->entry;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n",
				entry->length, peer_id);

		ret = sendfile(fd, img_fd, &pkt->img_off, entry->length);
		if (ret < 0) {
			pr_perror("Failed to sendfile packet");
			return -1;
		}
		if (ret != entry->length) {
			pr_err("Restored skb trimmed to %d/%d\n",
					ret, entry->length);
			return -1;
		}
		list_del(&pkt->list);
		xfree(pkt);
	}

	close(img_fd);
	return 0;
}
