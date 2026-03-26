#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mqueue.h>

#include "imgset.h"
#include "files.h"
#include "image.h"
#include "log.h"
#include "util.h"
#include "xmalloc.h"
#include "posix-mqueue.h"
#include "protobuf.h"
#include "rst-malloc.h"
#include "common/list.h"

/*
 * MQ_IOC_BULK_PEEK is a custom kernel ioctl that non-destructively reads
 * messages from a POSIX mqueue.  Define it locally if the kernel headers
 * do not expose it yet.
 */
#ifndef MQ_IOC_BULK_PEEK
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

/* Set in mq_peek_msg_hdr.flags when the message continues in the next chunk. */
#define MQ_PEEK_FLAG_HAS_MORE  BIT(0)
#define ALIGN8(x) (((x) + 7) & ~(size_t)7)

struct mq_bulk_peek_args {
	uint32_t start_idx;
	uint32_t start_offset;
	uint32_t max_count;
	uint32_t reserved_in;
	uint64_t buf_ptr;
	uint64_t buf_size;
	uint32_t out_count;
	uint32_t next_idx;
	uint32_t next_offset;
	uint32_t reserved_out;
};

struct mq_peek_msg_hdr {
	uint32_t total_msg_len;
	uint32_t chunk_len;
	uint32_t msg_prio;
	uint32_t flags;
	uint8_t  payload[];
};

#define MQ_IOC_BULK_PEEK _IOWR('M', 1, struct mq_bulk_peek_args)
#endif /* MQ_IOC_BULK_PEEK */

#define PEEK_BUF_SIZE 8192
int pmq_peek_messages(int fd, struct mqueue_message *msgs, long nmsgs, long msgsize)
{
	char peek_buf[PEEK_BUF_SIZE];
	struct mq_bulk_peek_args args = {0};
	uint32_t current_msg_idx = 0;
	size_t current_msg_offset = 0;
	size_t offset = 0;
	size_t raw_size = 0;

	args.buf_ptr = (uint64_t)(uintptr_t)peek_buf;
	args.buf_size = sizeof(peek_buf);
	args.max_count = 128;

	pr_info("Peeking %ld messages from mqueue fd %d\n", nmsgs, fd);

	/*
	 * Issue repeated ioctl calls until all nmsgs messages have been read.
	 * Each call fills peek_buf with as many message chunks as fit; the
	 * kernel sets next_idx/next_offset so the following call resumes
	 * exactly where this one stopped.
	 */
	while (current_msg_idx < (uint32_t)nmsgs) {
		if (ioctl(fd, MQ_IOC_BULK_PEEK, &args) < 0) {
			pr_perror("Failed to bulk peek mqueue (fd: %d)", fd);
			return -1;
		}

		if (args.out_count == 0) {
			pr_err("Unexpected end of queue. Expected %ld, got %u\n",
			       nmsgs, current_msg_idx);
			return -1;
		}

		offset = 0;
		for (uint32_t i = 0; i < args.out_count; i++) {
			struct mq_peek_msg_hdr *hdr =
				(struct mq_peek_msg_hdr *)(peek_buf + offset);

			/*
			 * Allocate the destination buffer on the first chunk of
			 * each message (current_msg_offset == 0).  Subsequent
			 * chunks of the same message append to it.
			 */
			if (current_msg_offset == 0) {
				msgs[current_msg_idx].prio = hdr->msg_prio;
				msgs[current_msg_idx].len = hdr->total_msg_len;
				msgs[current_msg_idx].data = xmalloc(hdr->total_msg_len + 1);
				if (!msgs[current_msg_idx].data)
					return -1;
			}

			memcpy(msgs[current_msg_idx].data + current_msg_offset,
			       hdr->payload, hdr->chunk_len);

			if (hdr->flags & MQ_PEEK_FLAG_HAS_MORE) {
				/* More chunks belong to the same message. */
				current_msg_offset += hdr->chunk_len;
			} else {
				/* Message fully reassembled; advance to next. */
				current_msg_idx++;
				current_msg_offset = 0;
			}

			/* Each header+payload is 8-byte aligned in the buffer. */
			raw_size = sizeof(*hdr) + hdr->chunk_len;
			offset += ALIGN8(raw_size);
		}

		/* Advance the cursor for the next ioctl call. */
		args.start_idx = args.next_idx;
		args.start_offset = args.next_offset;
	}

	return 0;
}

static int dump_one_pmq_fd(int lfd, u32 id, const struct fd_parms *p)
{
	IpcnsPmqDataEntry pmq = IPCNS_PMQ_DATA_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct mqueue_message *msgs = NULL;
	struct mq_attr attr;
	char path[PATH_MAX];
	int ret = -1;
	int i;

	if (mq_getattr((mqd_t)lfd, &attr) < 0) {
		pr_perror("Can't get mqueue attributes for fd %d", lfd);
		return -1;
	}

	if (read_fd_link(lfd, path, sizeof(path)) < 0) {
		pr_err("Can't read link for pmq fd %d\n", lfd);
		return -1;
	}

	/*
	 * read_fd_link() returns the full VFS path, e.g.
	 * /dev/mqueue/zdtm_posix_mqueue_test.  mq_open(3) and mq_unlink(3)
	 * only accept the POSIX name (/queue_name, no directory prefix), so
	 * take the last slash-prefixed component.
	 */
	pmq.name = strrchr(path, '/');
	if (!pmq.name) {
		pr_err("Unexpected mqueue path (no slash): %s\n", path);
		return -1;
	}

	pmq.id = id;
	pmq.mq_maxmsg = attr.mq_maxmsg;
	pmq.mq_msgsize = attr.mq_msgsize;
	pmq.mq_curmsgs = attr.mq_curmsgs;
	pmq.flags = p->flags;
	pmq.fown = (FownEntry *)&p->fown;

	if (pmq.mq_curmsgs > 0) {
		msgs = xzalloc(pmq.mq_curmsgs * sizeof(*msgs));
		if (!msgs)
			goto out;

		/*
		 * Peek all messages non-destructively via the bulk ioctl.
		 * The kernel returns them in priority-then-FIFO order, which
		 * is exactly the order mq_receive() would dequeue them.
		 */
		if (pmq_peek_messages(lfd, msgs, pmq.mq_curmsgs, pmq.mq_msgsize)) {
			pr_err("Failed to peek messages for mqueue %s\n", path);
			goto out;
		}

		pmq.n_messages = pmq.mq_curmsgs;
		pmq.messages = xmalloc(pmq.n_messages * sizeof(PosixMqueueMsgEntry *));
		if (!pmq.messages)
			goto out;

		/* Wrap each raw message into a protobuf entry. */
		for (i = 0; i < (int)pmq.n_messages; i++) {
			pmq.messages[i] = xmalloc(sizeof(PosixMqueueMsgEntry));
			if (!pmq.messages[i])
				goto out;
			posix_mqueue_msg_entry__init(pmq.messages[i]);

			pmq.messages[i]->msg_prio = msgs[i].prio;
			pmq.messages[i]->msg_len  = msgs[i].len;

			/* msg_data borrows the pointer; freed in the out: block. */
			pmq.messages[i]->msg_data.len = msgs[i].len;
			pmq.messages[i]->msg_data.data = (uint8_t *)msgs[i].data;
		}
	}

	fe.type = FD_TYPES__PQEFD;
	fe.id = id;
	fe.pqmfd = &pmq;

	pr_info("Dumping POSIX mqueue '%s' id %#x flags %o msgs %lu\n",
		path, id, p->flags, (unsigned long)pmq.mq_curmsgs);

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);

out:
	if (msgs) {
		for (i = 0; i < (int)pmq.mq_curmsgs; i++)
			xfree(msgs[i].data);
		xfree(msgs);
	}

	if (pmq.messages) {
		for (i = 0; i < (int)pmq.n_messages; i++)
			xfree(pmq.messages[i]);
		xfree(pmq.messages);
	}

	return ret;
}

const struct fdtype_ops pmq_dump_ops = {
	.type = FD_TYPES__PQEFD,
	.dump = dump_one_pmq_fd,
};

/* Restore */

static LIST_HEAD(rst_pmqueues);

static int pmq_open(struct file_desc *d, int *new_fd)
{
	struct mqueue_file_info *info;
	IpcnsPmqDataEntry *pmq;
	struct mq_attr attr;
	mqd_t mq;
	int i;

	info = container_of(d, struct mqueue_file_info, d);
	pmq = info->mfe;

	attr.mq_maxmsg  = pmq->mq_maxmsg;
	attr.mq_msgsize = pmq->mq_msgsize;
	attr.mq_flags   = 0;
	attr.mq_curmsgs = 0;

	/*
	 * Unlink any pre-existing queue: after dump the process is killed
	 * but the named queue lingers.  We must recreate it from scratch
	 * so the saved messages are the only ones present.
	 */
	mq_unlink(pmq->name);

	mq = mq_open(pmq->name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK,
		     0666, &attr);
	if (mq == (mqd_t)-1) {
		pr_perror("Failed to create mqueue %s", pmq->name);
		return -1;
	}

	/*
	 * Replay messages in the order they were saved (priority-then-FIFO),
	 * so the restored queue matches the original dequeue order exactly.
	 */
	for (i = 0; i < (int)pmq->n_messages; i++) {
		PosixMqueueMsgEntry *msg = pmq->messages[i];

		if (mq_send(mq, (char *)msg->msg_data.data,
			    msg->msg_data.len, msg->msg_prio) < 0) {
			pr_perror("Failed to restore message %d to %s", i, pmq->name);
			mq_close(mq);
			return -1;
		}
	}

	if (rst_file_params(mq, pmq->fown, pmq->flags)) {
		pr_perror("Can't restore params for mqueue %s", pmq->name);
		mq_close(mq);
		return -1;
	}

	pr_info("Restored POSIX mqueue '%s' with %zu messages\n",
		pmq->name, pmq->n_messages);

	list_add_tail(&info->rlist, &rst_pmqueues);

	*new_fd = mq;
	return 0;
}

static struct file_desc_ops pmq_desc_ops = {
	.type = FD_TYPES__PQEFD,
	.open = pmq_open,
};

static int collect_one_pmq(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct mqueue_file_info *info = o;

	info->mfe = pb_msg(msg, IpcnsPmqDataEntry);
	info->fd = -1;

	return file_desc_add(&info->d, info->mfe->id, &pmq_desc_ops);
}

struct collect_image_info pmqfd_cinfo = {
	.fd_type  = CR_FD_FILES,
	.pb_type  = PB_IPCNS_PMQ_DATA,
	.priv_size = sizeof(struct mqueue_file_info),
	.collect  = collect_one_pmq,
};
