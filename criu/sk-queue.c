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
#include "kerndat.h"
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
#include "pidfd.h"
#include "files.h"
#include "protobuf.h"
#include "images/sk-packet.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "skqueue: "

/*
 * Result of inspecting the SCM_PIDFD cmsg the kernel hands us for a peeked
 * packet. When the kernel gives a definitive answer about the sender we use
 * it instead of the pstree-lookup-miss heuristic.
 */
struct pidfd_probe {
	bool probed;   /* SCM_PIDFD gave a definitive liveness answer */
	bool stale;    /* ... and the sender is dead */
	bool has_exit; /* ... and we know its wait(2) exit status */
	int exit_code;
	bool has_ino;  /* ... and we could read the pidfs ino of its struct pid */
	uint64_t ino;
};

struct sk_packet {
	struct list_head list;
	SkPacketEntry *entry;
	union {
		char *data;
		size_t data_off;
	};
	unsigned scm_len;
	int *scm;
	bool pidfd_probed; /* SCM_PIDFD gave a definitive answer for this pkt */
	bool pidfd_stale;  /* ... and the sender is dead */
	/*
	 * Dump side: pidfs state of the sender's struct pid, preallocated
	 * along with the packet and attached to the entry once we know the
	 * sender is dead (see sk_queue_post_actions()).
	 */
	PidfsAttrEntry *dead_pid;
	/*
	 * Restore side: the stand-in for the dead sender of this packet, as
	 * an index into the shared dead pid table, or -1 for a live sender.
	 */
	int dead_pid_idx;
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
	 * Claim a stand-in process for the sender now, while the whole restore
	 * is still one process: everything else that refers to this dead
	 * struct pid claims the same one, and by the time the queue is
	 * refilled the stand-in is already there to be pointed at.
	 */
	pkt->dead_pid_idx = -1;
	if (pkt->entry->dead_pid) {
		PidfsAttrEntry *dp = pkt->entry->dead_pid;

		pkt->dead_pid_idx = dead_pid_add(dp->ino, dp->has_ino, dp);
		if (pkt->dead_pid_idx < 0) {
			xfree(pkt->data);
			return -1;
		}
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

	pr_info("Dumping scm rights (nested fds) id_for 0x%x\n", pe->id_for);

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

			if (ue->pid != 0) {
				/*
				 * Look the sender up in the dumped tree first. A
				 * hit is authoritative even when the pidfd probe
				 * reported an exit: CRIU dumps and restores
				 * zombies, so a queued packet from an unreaped
				 * zombie sender that is still in the tree is best
				 * fixed up to the restored task's vpid rather than
				 * replaced by a helper. A zero pid is not a pid to
				 * look up at all, see below.
				 */
				for_each_pstree_item(item) {
					if (item->pid->real == ue->pid) {
						found = item;
						break;
					}
				}
			}

			if (found) {
				pr_debug("ucred: Fixup ucred pids %d -> %d\n",
					 ue->pid, vpid(found));
				ue->pid = vpid(found);
			} else if (pkt->pidfd_stale) {
				/*
				 * PIDFD_GET_INFO (or a negative SCM_PIDFD payload)
				 * proved the sender is dead, and it is not in the
				 * dumped tree. The pid number is a dump host real
				 * pid with no meaning in the image, so zero it and
				 * record what is left of the sender instead: the
				 * pidfs state of its struct pid. Restore stands in
				 * for it with a process that dies the same way.
				 */
				pr_debug("ucred: Sender pid %d is dead (pidfd), marking packet stale on id_for %x\n",
					 ue->pid, pkt->entry->id_for);
				pkt->entry->dead_pid = pkt->dead_pid;
				ue->pid = 0;
			} else if (ue->pid != 0) {
				/*
				 * A sender that is neither in the dumped tree nor
				 * dead is one nothing can be done for: it won't
				 * exist after restore and there is no faithful way
				 * to reattach its pid, so drop the packet rather
				 * than mislabel it as stale. Without a pidfd verdict
				 * (the receiver lacks SO_PASSPIDFD) we can't tell
				 * the two apart, which is the pre-existing
				 * SCM_CREDENTIALS behaviour.
				 */
				if (pkt->pidfd_probed)
					pr_warn("ucred: Sender pid %d is alive but outside the dumped tree, dropping packet\n",
						ue->pid);
				else
					pr_warn("ucred: Can't find process with pid %d, ignoring packet\n",
						ue->pid);
				goto next;
			}

			/*
			 * A zero pid left here is a packet we know nothing more
			 * about, so write it exactly as it was dumped. Note that
			 * it is not a pid to look up and not proof that the skb
			 * carries no struct pid: scm_set_cred() keeps the struct
			 * pid and derives the number from it with pid_vnr(),
			 * which yields 0 for a pid not nameable in the pid
			 * namespace we peeked the queue from. Where a pidfd
			 * proves such a pid dead we prefer a stand-in over a bare
			 * packet, which is what the stale case above does.
			 */
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

static int queue_packet_entry(SkPacketEntry *entry, void *data, size_t len, struct pidfd_probe *probe)
{
	PidfsAttrEntry *pei;
	SkPacketEntry *pe;
	SkUcredEntry *ue;
	void *p;
	struct sk_packet *pkt;
	size_t sum = 0;
	int i, j;

	sum += sizeof(*pkt);
	sum += sizeof(*pkt->entry);
	sum += sizeof(*pkt->entry->ucred);
	sum += sizeof(*pkt->dead_pid);
	sum += len;

	pkt = xmalloc(sum);
	if (!pkt)
		return -ENOMEM;

	pe = (void *)pkt + sizeof(*pkt);
	ue = (void *)pe + sizeof(*pe);
	pei = (void *)ue + sizeof(*ue);
	p = (void *)pei + sizeof(*pei);

	sk_packet_entry__init(pe);
	sk_ucred_entry__init(ue);
	pidfs_attr_entry__init(pei);

	pkt->entry = pe;
	pkt->data_off = p - (void *)pkt;
	pkt->pidfd_probed = probe->probed;
	pkt->pidfd_stale = probe->stale;
	pkt->dead_pid = pei;
	pkt->dead_pid_idx = -1;

	pe->id_for = entry->id_for;
	pe->length = entry->length;
	pe->ucred = ue;
	ue->uid = entry->ucred->uid;
	ue->gid = entry->ucred->gid;
	ue->pid = entry->ucred->pid;
	if (probe->has_exit) {
		pei->has_exit_code = true;
		pei->exit_code = probe->exit_code;
	}
	if (probe->has_ino) {
		pei->has_ino = true;
		pei->ino = probe->ino;
	}
	/*
	 * A fallback identity for when there is no ino, which is every dead
	 * sender on a kernel that mints no pidfd for a reaped one. Without it
	 * each packet of a single dead sender would claim a stand-in process
	 * of its own on restore. Only read back where the packet turns out to
	 * be stale, see sk_queue_post_actions().
	 */
	if (entry->ucred->pid) {
		pei->has_dump_pid = true;
		pei->dump_pid = entry->ucred->pid;
	}

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

static int dump_packet_cmsg(struct msghdr *mh, SkPacketEntry *pe, int flags, struct pidfd_probe *probe)
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
			} else if (ch->cmsg_len == CMSG_LEN(sizeof(int)) &&
				   ch->cmsg_type == SCM_PIDFD) {
				int pidfd = *(int *)CMSG_DATA(ch);

				/*
				 * The skb pid the pidfd refers to is dumped
				 * from the SCM_CREDENTIALS cmsg (SO_PASSCRED
				 * is enabled for the peek when the socket has
				 * SO_PASSPIDFD). The pidfd itself is the most
				 * authoritative liveness signal we get for the
				 * sender, so inspect it before closing the fd
				 * that recvmsg installed.
				 *
				 * A negative payload is pidfd_prepare()'s raw
				 * return value. Only two of the errors it can
				 * fail with say anything about the sender:
				 * kernels < 6.17 refuse to mint a pidfd for an
				 * already reaped one (-EINVAL before v6.10,
				 * -ESRCH after). The rest are about us -- a
				 * full fd table, no memory -- so bail out
				 * rather than declare a live sender dead and
				 * quietly stand in for it.
				 *
				 * -EINVAL is the looser of the two: before
				 * v6.10 it also meant "this struct pid is not
				 * a thread-group leader". A sender with
				 * CAP_SYS_ADMIN can produce that by spoofing a
				 * tid in SCM_CREDENTIALS, since scm_check_creds()
				 * lets it name any pid and __scm_send() resolves
				 * the number with a bare find_get_pid(). We would
				 * then stand in for a live thread. Nothing else
				 * distinguishes the two cases, and a real one is
				 * far more likely, so take the reaped reading.
				 */
				if (pidfd < 0 && pidfd != -EINVAL && pidfd != -ESRCH) {
					pr_err("Can't get a pidfd of the sender: %d\n", pidfd);
					return -1;
				}

				probe->probed = true;
				if (pidfd < 0) {
					/* Definitively dead, and no fd to close. */
					probe->stale = true;
				} else {
					int exit_code;

					/*
					 * Only probe the exit status when the
					 * kernel is known to support the ioctl;
					 * otherwise pidfd_query_exit() would fail
					 * once per packet. A pidfd >= 0 on a kernel
					 * without PIDFD_GET_INFO means the sender is
					 * still alive (reaped senders yield the
					 * negative payload handled above).
					 */
					if (kdat.has_pidfd_get_info && pidfd_query_exit(pidfd, &exit_code) > 0) {
						probe->stale = true;
						probe->has_exit = true;
						probe->exit_code = exit_code;
					}

					/*
					 * The pidfs ino is what identifies the
					 * sender's struct pid: it is the only
					 * thing that tells two dead senders
					 * apart, and the only thing that ties
					 * this packet to a pidfd of the same
					 * process elsewhere in the dump. Read
					 * it while we still hold the fd; a
					 * failure is not fatal, it only costs
					 * that sharing.
					 */
					if (pidfd_query_ino(pidfd, &probe->ino) == 0)
						probe->has_ino = true;

					pr_debug("Closing pidfd %d received on queue peek\n", pidfd);
					close(pidfd);
				}
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

static int dump_sk_queue_packet(int sock_fd, int sock_id, void *data, int size, int flags)
{
	SkPacketEntry pe = SK_PACKET_ENTRY__INIT;
	struct pidfd_probe probe = {};
	int ret, exit_code = -1;
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

	pe.id_for = sock_id;

	ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
	if (!ret) {
		/*
		 * It means, that peer has performed an
		 * orderly shutdown, so we're done.
		 */
		return 1;
	} else if (ret < 0) {
		if (errno == EAGAIN)
			return 1;

		pr_perror("recvmsg fail: error");
		return -1;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		/*
		 * DGRAM truncated. This should not happen. But we have
		 * to check...
		 */
		pr_err("recvmsg failed: truncated\n");
		return -1;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		/*
		 * Control data was truncated: the kernel dropped part of
		 * the ancillary messages (and may have installed then
		 * leaked passed fds). We would misread the sender's
		 * liveness from a missing SCM_PIDFD, so bail out.
		 */
		pr_err("recvmsg failed: control data truncated\n");
		return -1;
	}

	ret = dump_packet_cmsg(&msg, &pe, flags, &probe);
	if (ret < 0)
		goto cleanup_packet;

	if (ret > 0) {
		if (ret == 1) {
			if (queue_packet_entry(&pe, data, pe.length, &probe))
				goto cleanup_packet;
		}
		exit_code = 0;
		goto cleanup_packet;
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
	if (ret < 0)
		goto cleanup_packet;

	ret = write_img_buf(img_from_set(glob_imgset, CR_FD_SK_QUEUES), data, pe.length);
	if (ret < 0)
		goto cleanup_packet;

	exit_code = 0;
cleanup_packet:
	if (pe.scm)
		release_cmsg(&pe);
	xfree(pe.ucred);
	return exit_code;
}

int dump_sk_queue(int sock_fd, int sock_id, int flags)
{
	int ret, size, orig_peek_off;
	int exit_code = -1;
	int passcred_set = 0;
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
		return -1;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return -1;
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
		goto err_free;
	}

	/*
	 * If the socket has SO_PASSPIDFD but not SO_PASSCRED, peeked packets
	 * carry an SCM_PIDFD cmsg only, which loses the skb uid/gid and needs
	 * a pidfd -> pid conversion. Both PASS* options are just recvmsg-time
	 * views of the same pid/creds the kernel attached to the skb at send
	 * time, so temporarily enable SO_PASSCRED to make every packet yield
	 * a full SCM_CREDENTIALS cmsg instead.
	 *
	 * There is no family check here because dump_sk_queue() is only ever
	 * called for unix sockets. Should that change, gate this on AF_UNIX
	 * the way dump_socket_opts() does: since Linux 6.16 get/setsockopt of
	 * SO_PASSPIDFD fails with EOPNOTSUPP on anything else.
	 */
	if (kdat.has_so_passpidfd) {
		int passpidfd = 0, passcred = 0;

		if (dump_opt(sock_fd, SOL_SOCKET, SO_PASSPIDFD, &passpidfd))
			goto err_set_sock;

		if (dump_opt(sock_fd, SOL_SOCKET, SO_PASSCRED, &passcred))
			goto err_set_sock;

		if (passpidfd && !passcred) {
			int one = 1;

			if (restore_opt(sock_fd, SOL_SOCKET, SO_PASSCRED, &one))
				goto err_set_sock;
			passcred_set = 1;
		}
	}

	while (1) {
		ret = dump_sk_queue_packet(sock_fd, sock_id, data, size, flags);
		if (ret == 1)
			break;
		else if (ret == -1)
			goto err_set_sock;
	}
	exit_code = 0;

err_set_sock:
	if (passcred_set) {
		int zero = 0;

		if (restore_opt(sock_fd, SOL_SOCKET, SO_PASSCRED, &zero))
			exit_code = -1;
	}
	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		ret = -1;
	}
err_free:
	xfree(data);
	return exit_code;
}

static int send_one_pkt(int fd, struct sk_packet *pkt, pid_t dead_pid)
{
	int ret;
	SkPacketEntry *entry = pkt->entry;
	struct msghdr mh = {};
	size_t msg_controllen = 0;
	struct iovec iov;
	char cmsg[CMSG_MAX_SIZE];
	struct cmsghdr *ch = NULL;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	iov.iov_base = pkt->data;
	iov.iov_len = entry->length;

	/*
	 * We need to init msg_control, msg_controllen
	 * fields to make CMSG_*() helpers work correctly
	 * Later, just before sendmsg we have to set
	 * msg_controllen to actual summary length of SCMs.
	 */
	mh.msg_control = cmsg;
	mh.msg_controllen = sizeof(cmsg);
	memset(cmsg, 0, sizeof(cmsg));

	if (pkt->scm != NULL) {
		ScmEntry *se;
		struct cmsghdr *sch;

		BUG_ON(!entry->n_scm);
		se = entry->scm[0];

		ch = CMSG_FIRSTHDR(&mh);
		BUG_ON(!ch);

		sch = (struct cmsghdr *)pkt->scm;
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_RIGHTS;

		BUG_ON(msg_controllen +
		       CMSG_SPACE(se->n_rights * sizeof(int)) >= sizeof(cmsg));
		memcpy(CMSG_DATA(ch), CMSG_DATA(sch), se->n_rights * sizeof(int));

		ch->cmsg_len = CMSG_LEN(se->n_rights * sizeof(int));
		msg_controllen += CMSG_SPACE(se->n_rights * sizeof(int));
	}

	/*
	 * Don't try to use sendfile here, because it use sendpage() and
	 * all data are split on pages and a new skb is allocated for
	 * each page. It creates a big overhead on SNDBUF.
	 * sendfile() isn't suitable for DGRAM sockets, because message
	 * boundaries messages should be saved.
	 */

	/*
	 * Note what we cannot express here: a packet whose skb carried no
	 * struct pid at all. We send it with no SCM_CREDENTIALS, and
	 * unix_maybe_add_creds() then attaches *our* tgid to the skb whenever
	 * either socket may pass credentials, so a receiver that saw no
	 * SCM_PIDFD before the dump can get a live one after it. Sending an
	 * explicit pid of 0 instead is not an option: __scm_send() resolves
	 * the number with find_get_pid(), which fails with -ESRCH for 0.
	 */
	if (entry->ucred && (entry->ucred->pid || entry->dead_pid)) {
		struct ucred *ucred;

		ch = ch ? CMSG_NXTHDR(&mh, ch) : CMSG_FIRSTHDR(&mh);
		BUG_ON(!ch);

		ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		ch->cmsg_level = SOL_SOCKET;
		ch->cmsg_type = SCM_CREDENTIALS;

		BUG_ON(msg_controllen +
		       CMSG_SPACE(sizeof(struct ucred)) >= sizeof(cmsg));

		ucred = (struct ucred *)CMSG_DATA(ch);
		if (entry->dead_pid) {
			/*
			 * The sender died before the dump. Attach the pid of
			 * the process standing in for it to the skb; that
			 * process is disposed of once the queue is refilled,
			 * so a receiver with SO_PASSPIDFD gets a pidfd that is
			 * stale, and reports the original exit status, just as
			 * before the dump.
			 */
			BUG_ON(dead_pid <= 0);
			ucred->pid = dead_pid;
		} else {
			ucred->pid = entry->ucred->pid;
		}
		ucred->uid = entry->ucred->uid;
		ucred->gid = entry->ucred->gid;
		msg_controllen += CMSG_SPACE(sizeof(struct ucred));

		pr_debug("\tsend creds pid %d uid %d gid %d%s\n",
			 ucred->pid,
			 ucred->uid,
			 ucred->gid,
			 entry->dead_pid ? " (dead pid stand-in)" : "");
	}

	mh.msg_controllen = msg_controllen;

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
		pid_t dead_pid = 0;

		if (entry->id_for != peer_id)
			continue;

		if (pkt->dead_pid_idx >= 0) {
			dead_pid = dead_pid_get(pkt->dead_pid_idx);
			if (dead_pid < 0) {
				ret = -1;
				goto out;
			}
		}

		pr_info("\tRestoring %d-bytes skb for %u\n", (unsigned int)entry->length, peer_id);

		ret = send_one_pkt(fd, pkt, dead_pid);
		if (ret)
			goto out;

		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	ret = 0;
out:
	/*
	 * The stand-in processes are not disposed of here. Each of these skbs
	 * now holds a reference on a stand-in's struct pid, and so may a pidfd
	 * file some other task has yet to restore -- for the same dead process,
	 * which is the whole point of keying them on the pidfs ino. They are
	 * killed once every task has restored everything, and only then does
	 * the pidfd a receiver mints go stale, with the original exit status,
	 * exactly as it was before the dump.
	 */
	return ret;
}

int prepare_scms(void)
{
	struct sk_packet *pkt;

	pr_info("Preparing SCMs\n");
	list_for_each_entry_reverse(pkt, &packets_list, list) {
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
