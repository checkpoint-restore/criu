#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "common/list.h"
#include "imgset.h"
#include "image.h"
#include "servicefd.h"
#include "cr_options.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"
#include "xmalloc.h"
#include "namespaces.h"
#include "pstree.h"
#include "util.h"

#include "sk-queue.h"
#include "files.h"
#include "protobuf.h"
#include "images/sk-packet.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "skqueue: "

struct sk_packet {
	struct list_head list;
	SkPacketEntry *entry;
	union {
		char *data;
		size_t data_off;
	};
	unsigned scm_len;
	int *scm;
};

static LIST_HEAD(packets_list);

static int collect_one_packet(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	struct sk_packet *pkt = obj;

	pkt->entry = pb_msg(msg, SkPacketEntry);
	pkt->scm = NULL;
	pkt->data = xmalloc(pkt->entry->length);
	if (pkt->data == NULL)
		return -1;

	/*
	 * See dump_packet_cmsg() -- only SCM_RIGHTS are supported and
	 * only 1 of that kind is possible, thus not more than 1 SCMs
	 * on a packet.
	 */
	if (pkt->entry->n_scm > 1) {
		pr_err("More than 1 SCM is not possible\n");
		xfree(pkt->data);
		return -1;
	}

	if (read_img_buf(img, pkt->data, pkt->entry->length) != 1) {
		xfree(pkt->data);
		pr_perror("Unable to read packet data");
		return -1;
	}

	/*
	 * NOTE: packet must be added to the tail. Otherwise sequence
	 * will be broken.
	 */
	list_add_tail(&pkt->list, &packets_list);

	return 0;
}

struct collect_image_info sk_queues_cinfo = {
	.fd_type = CR_FD_SK_QUEUES,
	.pb_type = PB_SK_QUEUES,
	.priv_size = sizeof(struct sk_packet),
	.collect = collect_one_packet,
};

static int dump_scm_rights(struct cmsghdr *ch, SkPacketEntry *pe)
{
	int nr_fds, *fds, i;
	void *buf;
	ScmEntry *scme;

	nr_fds = (ch->cmsg_len - sizeof(*ch)) / sizeof(int);
	fds = (int *)CMSG_DATA(ch);

	buf = xmalloc(sizeof(ScmEntry) + nr_fds * sizeof(uint32_t));
	if (!buf)
		return -1;

	scme = xptr_pull(&buf, ScmEntry);
	scm_entry__init(scme);
	scme->type = SCM_RIGHTS;
	scme->n_rights = nr_fds;
	scme->rights = xptr_pull_s(&buf, nr_fds * sizeof(uint32_t));

	for (i = 0; i < nr_fds; i++) {
		int ftyp;

		if (dump_my_file(fds[i], &scme->rights[i], &ftyp)) {
			xfree(scme);
			return -1;
		}
	}

	i = pe->n_scm++;
	if (xrealloc_safe(&pe->scm, pe->n_scm * sizeof(ScmEntry *))) {
		xfree(scme);
		return -1;
	}

	pe->scm[i] = scme;
	return 0;
}

static void release_cmsg(SkPacketEntry *pe)
{
	int i;

	for (i = 0; i < pe->n_scm; i++)
		xfree(pe->scm[i]);
	xfree(pe->scm);

	pe->n_scm = 0;
	pe->scm = NULL;
}

/*
 * Maximum size of the control messages. XXX -- is there any
 * way to get this value out of the kernel?
 *
 * The kernel limits SCM_RIGHTS to SCM_MAX_FD (253) file descriptors,
 * defined in include/net/scm.h. A single packet can carry multiple
 * SCM types simultaneously:
 *   - SCM_RIGHTS:      CMSG_SPACE(253 * sizeof(int)) = 1032 bytes
 *   - SCM_CREDENTIALS: CMSG_SPACE(sizeof(struct ucred)) = 32 bytes
 *   - SCM_PIDFD:       CMSG_SPACE(sizeof(int)) = 24 bytes
 *
 * Total worst case: ~1088 bytes. Round up to 2048 for safety.
 */
#define CMSG_MAX_SIZE 2048

int sk_queue_post_actions(void)
{
	struct sk_packet *pkt, *t;
	struct cr_img *img;
	int ret = 0;

	img = img_from_set(glob_imgset, CR_FD_SK_QUEUES);

	list_for_each_entry_safe(pkt, t, &packets_list, list) {
		if (!pkt->entry->ucred) {
			pr_err("ucred: corruption on id_for %x\n",
			       pkt->entry->id_for);
			ret = -1;
		}

		if (!ret) {
			struct pstree_item *item, *found = NULL;
			SkUcredEntry *ue = pkt->entry->ucred;

			for_each_pstree_item(item) {
				if (item->pid->real == ue->pid) {
					found = item;
					break;
				}
			}

			if (!found) {
				pr_warn("ucred: Can't find process with pid %d, ignoring packet\n",
					ue->pid);
				goto next;
			}

			pr_debug("ucred: Fixup ucred pids %d -> %d\n",
				 ue->pid, vpid(item));
			ue->pid = vpid(item);

			ret = pb_write_one(img, pkt->entry, PB_SK_QUEUES);
			if (ret < 0) {
				ret = -EIO;
				goto next;
			}

			ret = write_img_buf(img, (char *)pkt + pkt->data_off, pkt->entry->length);
			if (ret < 0) {
				ret = -EIO;
				goto next;
			}
		}

next:
		list_del(&pkt->list);
		if (pkt->entry)
			release_cmsg(pkt->entry);
		xfree(pkt);
	}
	return ret;
}

static int queue_packet_entry(SkPacketEntry *entry, void *data, size_t len)
{
	SkPacketEntry *pe;
	SkUcredEntry *ue;
	void *p;
	struct sk_packet *pkt;
	size_t sum = 0;
	int i, j;

	sum += sizeof(*pkt);
	sum += sizeof(*pkt->entry);
	sum += sizeof(*pkt->entry->ucred);
	sum += len;

	pkt = xmalloc(sum);
	if (!pkt)
		return -ENOMEM;

	pe = (void *)pkt + sizeof(*pkt);
	ue = (void *)pe + sizeof(*pe);
	p = (void *)ue + sizeof(*ue);

	sk_packet_entry__init(pe);
	sk_ucred_entry__init(ue);

	pkt->entry = pe;
	pkt->data_off = p - (void *)pkt;

	pe->id_for = entry->id_for;
	pe->length = entry->length;
	pe->ucred = ue;
	ue->uid = entry->ucred->uid;
	ue->gid = entry->ucred->gid;
	ue->pid = entry->ucred->pid;

	pe->n_scm = entry->n_scm;

	pe->scm = xmalloc(pe->n_scm * sizeof(ScmEntry *));
	if (!pe->scm) {
		xfree(pkt);
		return -1;
	}

	for (i = 0; i < entry->n_scm; i++) {
		void *buf;
		ScmEntry *scme;

		buf = xmalloc(sizeof(ScmEntry) + entry->scm[i]->n_rights * sizeof(uint32_t));
		if (!buf)
			goto err_free;

		scme = xptr_pull(&buf, ScmEntry);
		scm_entry__init(scme);
		scme->type = entry->scm[i]->type;
		scme->n_rights = entry->scm[i]->n_rights;
		scme->rights = xptr_pull_s(&buf, scme->n_rights * sizeof(uint32_t));

		for (j = 0; j < scme->n_rights; j++)
			scme->rights[j] = entry->scm[i]->rights[j];

		pe->scm[i] = scme;
	}


	memcpy(p, data, len);
	pr_debug("ucred: Queued ucred packet id_for %x\n",
		 pkt->entry->id_for);

	list_add_tail(&pkt->list, &packets_list);

	return 0;

err_free:
	for (j = 0; j < i; j++)
		xfree(pe->scm[j]);
	xfree(pe->scm);
	xfree(pkt);

	return -ENOMEM;
}

static int dump_sk_creds(struct ucred *ucred, SkPacketEntry *pe, int flags)
{
	SkUcredEntry *ent;

	ent = xmalloc(sizeof(*ent));
	if (!ent)
		return -1;

	sk_ucred_entry__init(ent);
	ent->uid = userns_uid(ucred->uid);
	ent->gid = userns_gid(ucred->gid);
	ent->pid = ucred->pid;

	if (pe->ucred)
		pr_warn("ucred: ucred already assigned\n");
	pe->ucred = ent;

	if (flags & SK_QUEUE_REAL_PID) {
		/*
		 * It is impossible to convert pid from real to virt,
		 * because virt pid-s are known for dumped task only.
		 * Thus defer the image writing, we will do it at the
		 * end, where all processes are collected already.
		 */
		pr_debug("ucred: Detected ucreds on id_for %x (uid %d gid %d pid %d)\n",
			 pe->id_for, ent->uid, ent->gid, ent->pid);
		return 1;
	} else {
		int pidns = root_ns_mask & CLONE_NEWPID;
		char path[64];
		int ret, _errno;

		/* Does a process exist? */
		if (ucred->pid == 0) {
			ret = 0;
		} else if (pidns) {
			snprintf(path, sizeof(path), "%d", ucred->pid);
			ret = faccessat(get_service_fd(CR_PROC_FD_OFF), path, R_OK, 0);
			_errno = errno;
		} else {
			snprintf(path, sizeof(path), "/proc/%d", ucred->pid);
			ret = access(path, R_OK);
			_errno = errno;
		}
		if (ret) {
			pr_warn("ucred: Unable to dump ucred for a dead process %d, ignoring packet: %s\n",
				ucred->pid, strerror(_errno));
			pe->ucred = NULL;
			xfree(ent);
			return 2;
		}
	}

	return 0;
}

static int dump_packet_cmsg(struct msghdr *mh, SkPacketEntry *pe, int flags)
{
	struct cmsghdr *ch;
	int n_rights = 0;
	int ret = 0;

	for (ch = CMSG_FIRSTHDR(mh); ch; ch = CMSG_NXTHDR(mh, ch)) {
		if (ch->cmsg_type == SCM_RIGHTS) {
			if (n_rights) {
				/*
				 * Even if user is sending more than one cmsg with
				 * rights, kernel merges them altogether on recv.
				 */
				pr_err("Unexpected 2nd SCM_RIGHTS from the kernel\n");
				return -1;
			}

			if (dump_scm_rights(ch, pe))
				return -1;

			n_rights++;
			continue;
		}

		if (ch->cmsg_level == SOL_SOCKET) {
			if (ch->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
			    ch->cmsg_type == SCM_CREDENTIALS) {
				struct ucred *ucred = (struct ucred *)CMSG_DATA(ch);

				ret |= dump_sk_creds(ucred, pe, flags);
				if (ret < 0)
					return -1;
				continue;
			} else if (ch->cmsg_type == SCM_TIMESTAMP ||
				   ch->cmsg_type == SCM_TIMESTAMPNS ||
				   ch->cmsg_type == SCM_TIMESTAMPING) {
				/*
				 * Allow to receive timestamps from the kernel.
				 */
				continue;
			}
		}

		pr_err("cmsg: len %lu type %d level %d\n",
		       (unsigned long)ch->cmsg_len, ch->cmsg_type, ch->cmsg_level);
		pr_err("Control messages in queue, not supported\n");
		return -1;
	}

	return ret;
}

int dump_sk_queue(int sock_fd, int sock_id, int flags)
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
		pr_perror("getsockopt failed");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a stream.
	 */
	data = xmalloc(size);
	if (!data)
		return -1;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail");
		goto err_brk;
	}

	pe.id_for = sock_id;

	while (1) {
		char cmsg[CMSG_MAX_SIZE];
		struct iovec iov = {
			.iov_base = data,
			.iov_len = size,
		};
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = &cmsg,
			.msg_controllen = sizeof(cmsg),
		};

		ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (!ret)
			/*
			 * It means, that peer has performed an
			 * orderly shutdown, so we're done.
			 */
			break;
		else if (ret < 0) {
			if (errno == EAGAIN)
				break; /* we're done */
			pr_perror("recvmsg fail: error");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM truncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_CTRUNC) {
			/*
			 * Control data truncated. This means the cmsg
			 * buffer was too small and SCM data (such as
			 * passed file descriptors) has been silently
			 * discarded by the kernel.
			 */
			pr_err("sys_recvmsg failed: control data truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}

		ret = dump_packet_cmsg(&msg, &pe, flags);
		if (ret < 0)
			goto err_set_sock;

		if (ret > 0) {
			if (ret == 1) {
				ret = -1;
				if (queue_packet_entry(&pe, data, pe.length))
					goto err_set_sock;
			}
			continue;
		}

		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		ret = write_img_buf(img_from_set(glob_imgset, CR_FD_SK_QUEUES), data, pe.length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		if (pe.scm)
			release_cmsg(&pe);
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		ret = -1;
	}
	if (pe.scm)
		release_cmsg(&pe);
err_brk:
	xfree(pe.ucred);
	xfree(data);
	return ret;
}

static int send_one_pkt(int fd, struct sk_packet *pkt)
{
	int ret;
	SkPacketEntry *entry = pkt->entry;
	struct msghdr mh = {};
	struct iovec iov;
	char cmsg[CMSG_MAX_SIZE];

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	iov.iov_base = pkt->data;
	iov.iov_len = entry->length;

	if (pkt->scm != NULL) {
		mh.msg_controllen = pkt->scm_len;
		mh.msg_control = pkt->scm;
	}

	/*
	 * Don't try to use sendfile here, because it use sendpage() and
	 * all data are split on pages and a new skb is allocated for
	 * each page. It creates a big overhead on SNDBUF.
	 * sendfile() isn't suitable for DGRAM sockets, because message
	 * boundaries messages should be saved.
	 */

	if (entry->ucred && entry->ucred->pid) {
		struct ucred *ucred;
		struct cmsghdr *ch;

		mh.msg_control = cmsg;
		mh.msg_controllen = sizeof(cmsg);

		ch = CMSG_FIRSTHDR(&mh);
		ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_CREDENTIALS;
		ucred = (struct ucred *)CMSG_DATA(ch);
		ucred->pid = entry->ucred->pid;
		ucred->uid = entry->ucred->uid;
		ucred->gid = entry->ucred->gid;
		mh.msg_controllen = CMSG_SPACE(sizeof(struct ucred));

		pr_debug("\tsend creds pid %d uid %d gid %d\n",
			 entry->ucred->pid,
			 entry->ucred->uid,
			 entry->ucred->gid);
	}
	ret = sendmsg(fd, &mh, 0);
	xfree(pkt->data);
	xfree(pkt->scm);
	if (ret < 0) {
		pr_perror("Failed to send packet");
		return -1;
	}
	if (ret != entry->length) {
		pr_err("Restored skb trimmed to %d/%d\n", ret, (unsigned int)entry->length);
		return -1;
	}

	return 0;
}

int restore_sk_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret = -1;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	if (restore_prepare_socket(fd))
		goto out;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		SkPacketEntry *entry = pkt->entry;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n", (unsigned int)entry->length, peer_id);

		ret = send_one_pkt(fd, pkt);
		if (ret)
			goto out;

		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	ret = 0;
out:
	return ret;
}

int prepare_scms(void)
{
	struct sk_packet *pkt;

	pr_info("Preparing SCMs\n");
	list_for_each_entry(pkt, &packets_list, list) {
		SkPacketEntry *pe = pkt->entry;
		ScmEntry *se;
		struct cmsghdr *ch;

		if (!pe->n_scm)
			continue;

		se = pe->scm[0]; /* Only 1 SCM is possible */

		if (se->type == SCM_RIGHTS) {
			pkt->scm_len = CMSG_SPACE(se->n_rights * sizeof(int));
			pkt->scm = xmalloc(pkt->scm_len);
			if (!pkt->scm)
				return -1;

			ch = (struct cmsghdr *)pkt->scm; /* FIXME -- via msghdr */
			ch->cmsg_level = SOL_SOCKET;
			ch->cmsg_type = SCM_RIGHTS;
			ch->cmsg_len = CMSG_LEN(se->n_rights * sizeof(int));

			if (unix_note_scm_rights(pe->id_for, se->rights, (int *)CMSG_DATA(ch), se->n_rights))
				return -1;

			continue;
		}

		pr_err("Unsupported scm %d in image\n", se->type);
		return -1;
	}

	return 0;
}
