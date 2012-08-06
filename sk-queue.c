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

#include "protobuf.h"
#include "protobuf/sk-packet.pb-c.h"

struct sk_packet {
	struct list_head	list;
	SkPacketEntry		*entry;
	off_t			img_off;
};

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
		ret = -1;
		pkt = xmalloc(sizeof(*pkt));
		if (!pkt) {
			pr_err("Failed to allocate packet header\n");
			break;
		}
		ret = pb_read_one_eof(fd, &pkt->entry, PB_SK_QUEUES);
		if (ret <= 0)
			break;

		pkt->img_off = lseek(fd, 0, SEEK_CUR);
		/*
		 * NOTE: packet must be added to the tail. Otherwise sequence
		 * will be broken.
		 */
		list_add_tail(&pkt->list, &packets_list);
		lseek(fd, pkt->entry->length, SEEK_CUR);
	}
	close(fd);
	xfree(pkt);

	return ret;
}

int dump_sk_queue(int sock_fd, int sock_id)
{
	SkPacketEntry pe = SK_PACKET_ENTRY__INIT;
	int ret, size, orig_peek_off;
	void *data;
	socklen_t tmp;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	orig_peek_off = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed\n");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a streem.
	 */
	data = xmalloc(size);
	if (!data)
		return -1;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail\n");
		goto err_brk;
	}

	pe.id_for = sock_id;

	while (1) {
		struct iovec iov = {
			.iov_base	= data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};

		ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
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

		ret = pb_write_one(fdset_fd(glob_fdset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		ret = write_img_buf(fdset_fd(glob_fdset, CR_FD_SK_QUEUES), data, pe.length);
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
	xfree(data);
	return ret;
}

static void sk_queue_data_handler(int fd, void *obj, int show_pages_content)
{
	SkPacketEntry *e = obj;

	if (show_pages_content) {
		pr_msg("\n");
		print_image_data(fd, e->length);
	} else
		lseek(fd, e->length, SEEK_CUR);
}

void show_sk_queues(int fd, struct cr_options *o)
{
	pb_show_plain_payload(fd, PB_SK_QUEUES,
			sk_queue_data_handler, o->show_pages_content);
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
		SkPacketEntry *entry = pkt->entry;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n",
			(unsigned int)entry->length, peer_id);

		ret = sendfile(fd, img_fd, &pkt->img_off, entry->length);
		if (ret < 0) {
			pr_perror("Failed to sendfile packet");
			return -1;
		}
		if (ret != entry->length) {
			pr_err("Restored skb trimmed to %d/%d\n",
			       ret, (unsigned int)entry->length);
			return -1;
		}
		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	close(img_fd);
	return 0;
}
