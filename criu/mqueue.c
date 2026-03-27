// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "protobuf.h"
#include "protobuf-desc.h"
#include "imgset.h"
#include "files.h"
#include "file-ids.h"
#include "util.h"
#include "log.h"
#include "mqueue.h"
#include "images/mqueue.pb-c.h"

/*
 * Holds one message drained from the queue during dump.
 * Messages are removed with mq_receive(), saved here,
 * written to the image, then put back with mq_send()
 * before CRIU resumes the target process.
 */
struct mq_peek_msg {
	char		*data;
	size_t		 len;
	unsigned int	 prio;
};

/*
 * Intrusive peek: drain @curmsgs messages from @fd, write
 * each to @img as a MqueueMessage protobuf entry, then
 * restore all messages back to the queue.
 *
 * The target process is frozen by ptrace for the whole
 * operation so no new messages can arrive in the window
 * between drain and refill.
 *
 * Returns number of messages written on success, -1 on error.
 */
int intrusive_mq_peek_all(mqd_t fd, struct cr_img *img,
			   long curmsgs, long msgsize)
{
	struct mq_peek_msg *saved;
	char *buf;
	int old_flags, n, i, ret;
	bool failed;

	if (curmsgs == 0)
		return 0;

	saved = xzalloc(curmsgs * sizeof(*saved));
	if (!saved)
		return -1;

	buf = xmalloc(msgsize);
	if (!buf) {
		xfree(saved);
		return -1;
	}

	ret	 = -1;
	n	 = 0;
	failed	 = false;

	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		pr_perror("fcntl F_GETFL");
		goto out;
	}

	if (fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
		pr_perror("fcntl O_NONBLOCK");
		old_flags = -1;
		goto out;
	}

	/* Step 1: drain queue, saving each message */
	while (n < curmsgs) {
		MqueueMessage msg = MQUEUE_MESSAGE__INIT;
		ssize_t len;

		len = mq_receive(fd, buf, msgsize, &saved[n].prio);
		if (len < 0) {
			if (errno != EAGAIN)
				pr_perror("mq_receive msg %d", n);
			break;
		}

		saved[n].data = xmemdup(buf, len);
		if (!saved[n].data) {
			pr_err("xmemdup failed for msg %d\n", n);
			n++;
			failed = true;
			break;
		}
		saved[n].len = len;
		n++;

		msg.priority	= saved[n - 1].prio;
		msg.body.data	= (uint8_t *)saved[n - 1].data;
		msg.body.len	= saved[n - 1].len;

		if (pb_write_one(img, &msg, PB_MQUEUE_MESSAGE) < 0) {
			pr_err("pb_write_one failed for msg %d\n", n - 1);
			failed = true;
			break;
		}

		pr_debug("Saved msg %d: prio=%u size=%zu\n",
			 n - 1, saved[n - 1].prio, len);
	}

	if (!failed)
		ret = n;

	/* Step 2: put all drained messages back */
	for (i = 0; i < n; i++) {
		if (!saved[i].data)
			continue;
		if (mq_send(fd, saved[i].data, saved[i].len,
			    saved[i].prio) < 0)
			pr_perror("mq_send msg %d", i);
	}

	if (old_flags >= 0)
		fcntl(fd, F_SETFL, old_flags);

out:
	xfree(buf);
	for (i = 0; i < curmsgs; i++)
		xfree(saved[i].data);
	xfree(saved);
	return ret;
}

/*
 * Restore messages from @img into the queue named by
 * @pmd->name.  The queue must already exist.
 */
int restore_pmq_messages(struct cr_img *img, PmqDataEntry *pmd)
{
	mqd_t mqd;
	int i, ret;
	MqueueMessage *msg;

	mqd = mq_open(pmd->name, O_WRONLY);
	if (mqd == (mqd_t)-1) {
		pr_perror("mq_open %s", pmd->name);
		return -1;
	}

	ret = 0;
	for (i = 0; i < pmd->curmsgs; i++) {
		ret = pb_read_one_eof(img, &msg, PB_MQUEUE_MESSAGE);
		if (ret <= 0) {
			pr_err("Failed to read msg %d for %s\n",
			       i, pmd->name);
			ret = -1;
			break;
		}

		ret = mq_send(mqd, (char *)msg->body.data,
			      msg->body.len, msg->priority);
		mqueue_message__free_unpacked(msg, NULL);

		if (ret < 0) {
			pr_perror("mq_send msg %d for %s", i, pmd->name);
			break;
		}
		ret = 0;
	}

	mq_close(mqd);
	return ret;
}

int dump_pmq_fd(int lfd, struct fd_parms *p, FdinfoEntry *e)
{
	PmqfdEntry mfe = PMQFD_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct mq_attr attr;
	struct cr_img *img;

	pr_info("Dumping pmqfd %d (%s)\n", lfd, p->link->name + 1);

	if (fd_id_generate_special(p, &mfe.id) < 0) {
		pr_err("Failed to generate fd id\n");
		return -1;
	}

	mfe.open_flags = p->flags;
	if (mq_getattr(lfd, &attr) == 0)
		mfe.mq_flags = attr.mq_flags;

	mfe.name = p->link->name + 1;
	mfe.fown = (FownEntry *)&p->fown;

	fe.id    = mfe.id;
	fe.type  = FD_TYPES__PMQFD;
	fe.pmqfd = &mfe;

	if (e) {
		e->type  = FD_TYPES__PMQFD;
		e->id    = mfe.id;
		e->fd    = p->fd;
		e->flags = p->fd_flags;
	}

	img = img_from_set(glob_imgset, CR_FD_FILES);
	if (!img) {
		pr_err("No FILES image\n");
		return -1;
	}

	return pb_write_one(img, &fe, PB_FILE);
}

static int open_pmq_fd(struct file_desc *d, int *new_fd)
{
	struct mqueue_file_info *info;
	PmqfdEntry *mfe;
	mqd_t mqd;

	info = container_of(d, struct mqueue_file_info, d);
	mfe  = info->mfe;

	pr_info("Restoring pmqfd: %s flags=%d\n",
		mfe->name, mfe->open_flags);

	mqd = mq_open(mfe->name, mfe->open_flags);
	if (mqd == (mqd_t)-1) {
		pr_perror("mq_open %s", mfe->name);
		return -1;
	}

	if (rst_file_params((int)mqd, mfe->fown, mfe->open_flags)) {
		pr_perror("rst_file_params for %s", mfe->name);
		mq_close(mqd);
		return -1;
	}

	*new_fd = (int)mqd;
	return 0;
}

static struct file_desc_ops pmqfd_desc_ops = {
	.type = FD_TYPES__PMQFD,
	.open = open_pmq_fd,
};

static int collect_one_pmq_fd(void *obj, ProtobufCMessage *msg,
			       struct cr_img *i)
{
	struct mqueue_file_info *info = obj;

	info->mfe = pb_msg(msg, PmqfdEntry);
	return file_desc_add(&info->d, info->mfe->id, &pmqfd_desc_ops);
}

struct collect_image_info pmqfd_cinfo = {
	.fd_type   = CR_FD_PMQFD,
	.pb_type   = PB_PMQFD,
	.priv_size = sizeof(struct mqueue_file_info),
	.collect   = collect_one_pmq_fd,
};