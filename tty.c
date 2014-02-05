#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <linux/major.h>

#include "compiler.h"
#include "asm/types.h"

#include "syscall.h"
#include "files.h"
#include "cr_options.h"
#include "fdset.h"
#include "servicefd.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "list.h"
#include "util-pie.h"
#include "proc_parse.h"
#include "file-ids.h"

#include "protobuf.h"
#include "protobuf/tty.pb-c.h"

#include "parasite-syscall.h"
#include "parasite.h"

#include "pstree.h"
#include "tty.h"

/*
 * Here are some notes about overall TTY c/r design. At moment
 * we support unix98 ptys only.
 *
 * Usually the PTYs represent a pair of links -- master peer and slave
 * peer. Master peer must be opened before slave. Internally, when kernel
 * creates master peer it also generates a slave interface in a form of
 * /dev/pts/N, where N is that named pty "index". Master/slave connection
 * unambiguously identified by this index.
 *
 * Still, one master can carry multiple slaves -- for example a user opens
 * one master via /dev/ptmx and appropriate /dev/pts/N in sequence.
 * The result will be the following
 *
 * master
 * `- slave 1
 * `- slave 2
 *
 * both slave will have same master index but different file descriptors.
 * Still inside the kernel pty parameters are same for both slaves. Thus
 * only one slave parameters should be restored, there is no need to carry
 * all parameters for every slave peer we've found.
 *
 */

#undef	LOG_PREFIX
#define LOG_PREFIX "tty: "

struct tty_info_entry {
	struct list_head		list;
	TtyInfoEntry			*tie;
};

struct tty_info {
	struct list_head		list;
	struct file_desc		d;

	TtyFileEntry			*tfe;
	TtyInfoEntry			*tie;

	struct list_head		sibling;
	int				major;

	bool				create;
	bool				inherit;
};

struct tty_dump_info {
	struct list_head		list;

	u32				id;
	pid_t				sid;
	pid_t				pgrp;
	int				fd;
	int				major;
};

static LIST_HEAD(all_tty_info_entries);
static LIST_HEAD(all_ttys);

/*
 * Usually an application has not that many ttys opened.
 * If this won't be enough in future we simply need to
 * change tracking mechanism to some more extendable.
 *
 * This particular bitmap requires 256 bytes of memory.
 * Pretty acceptable trade off in a sake of simplicity.
 */
#define MAX_TTYS 1024
static DECLARE_BITMAP(tty_bitmap, (MAX_TTYS << 1));
static DECLARE_BITMAP(tty_active_pairs, (MAX_TTYS << 1));

/*
 * /dev/ptmx is a shared resource between all tasks
 * so we need to serialize access to it.
 */
static mutex_t *tty_mutex;

int prepare_shared_tty(void)
{
	tty_mutex = shmalloc(sizeof(*tty_mutex));
	if (!tty_mutex) {
		pr_err("Can't create ptmx index mutex\n");
		return -1;
	}

	mutex_init(tty_mutex);

	return 0;
}

#define winsize_copy(d, s)				\
	do {						\
		ASSIGN_MEMBER((d), (s), ws_row);	\
		ASSIGN_MEMBER((d), (s), ws_col);	\
		ASSIGN_MEMBER((d), (s), ws_xpixel);	\
		ASSIGN_MEMBER((d), (s), ws_ypixel);	\
	} while (0)

#define termios_copy(d, s)				\
	do {						\
		struct termios __t;			\
							\
		memcpy((d)->c_cc, (s)->c_cc,		\
		       sizeof(__t.c_cc));		\
							\
		ASSIGN_MEMBER((d),(s), c_iflag);	\
		ASSIGN_MEMBER((d),(s), c_oflag);	\
		ASSIGN_MEMBER((d),(s), c_cflag);	\
		ASSIGN_MEMBER((d),(s), c_lflag);	\
		ASSIGN_MEMBER((d),(s), c_line);		\
	} while (0)

static int tty_gen_id(int major, int index)
{
	return (index << 1) + (major == TTYAUX_MAJOR);
}

static int tty_get_index(u32 id)
{
	return id >> 1;
}

/* Make sure the active pairs do exist */
int tty_verify_active_pairs(void)
{
	unsigned long i, unpaired_slaves = 0;

	for_each_bit(i, tty_active_pairs) {
		if ((i % 2) == 0) {
			if (test_bit(i + 1, tty_active_pairs)) {
				i++;
				continue;
			}

			if (!opts.shell_job) {
				pr_err("Found slave peer index %d without "
				       "correspond master peer\n",
				       tty_get_index(i));
				return -1;
			}

			pr_debug("Unpaired slave %d\n", tty_get_index(i));

			if (++unpaired_slaves > 1) {
				pr_err("Only one slave external peer "
				       "is allowed (index %d)\n",
				       tty_get_index(i));
				return -1;
			}
		}
	}

	return 0;
}

static int parse_index(u32 id, int lfd, int major)
{
	int index = -1;

	switch (major) {
	case TTYAUX_MAJOR:
		if (ioctl(lfd, TIOCGPTN, &index)) {
			pr_perror("Can't obtain ptmx index");
			return -1;
		}
		break;

	case UNIX98_PTY_SLAVE_MAJOR: {
		char path[PATH_MAX];
		char link[32];
		int len;

		snprintf(link, sizeof(link), "/proc/self/fd/%d", lfd);
		len = readlink(link, path, sizeof(path) - 1);
		if (len < 0) {
			pr_perror("Can't readlink %s", link);
			return -1;
		}
		path[len] = '\0';

		if (sscanf(path, PTS_FMT, &index) != 1) {
			pr_err("Unexpected format on path %s\n", path);
			return -1;
		}
		break;
	}
	}

	if (index > MAX_TTYS) {
		pr_err("Index %d on tty %x is too big\n", index, id);
		return -1;
	}

	return index;
}

static int tty_test_and_set(int bit, unsigned long *bitmap)
{
	int ret;

	BUG_ON(bit > (MAX_TTYS << 1));

	ret = test_bit(bit, bitmap);
	if (!ret)
		set_bit(bit, bitmap);
	return ret;
}

static int pty_open_ptmx_index(int flags, int index)
{
	int fds[32], i, ret = -1, cur_idx;

	memset(fds, 0xff, sizeof(fds));

	mutex_lock(tty_mutex);

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		fds[i] = open(PTMX_PATH, flags);
		if (fds[i] < 0) {
			pr_perror("Can't open %s", PTMX_PATH);
			break;
		}

		if (ioctl(fds[i], TIOCGPTN, &cur_idx)) {
			pr_perror("Can't obtain current index on %s", PTMX_PATH);
			break;
		}

		pr_debug("\t\tptmx opened with index %d\n", cur_idx);

		if (cur_idx == index) {
			pr_info("ptmx opened with index %d\n", cur_idx);
			ret = fds[i];
			fds[i] = -1;
			break;
		}

		/*
		 * Maybe indices are already borrowed by
		 * someone else, so no need to continue.
		 */
		if (cur_idx < index && (index - cur_idx) < ARRAY_SIZE(fds))
			continue;

		pr_err("Unable to open %s with specified index %d\n", PTMX_PATH, index);
		break;
	}

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	mutex_unlock(tty_mutex);

	return ret;
}

static int unlock_pty(int fd)
{
	const int lock = 0;

	/*
	 * Usually when ptmx opened it gets locked
	 * by kernel and we need to unlock it to be
	 * able to connect slave peer.
	 */
	if (ioctl(fd, TIOCSPTLCK, &lock)) {
		pr_err("Unable to unlock pty device via y%d\n", fd);
		return -1;
	}

	return 0;
}

static int lock_pty(int fd)
{
	const int lock = 1;

	if (ioctl(fd, TIOCSPTLCK, &lock)) {
		pr_err("Unable to lock pty device via %d\n", fd);
		return -1;
	}

	return 0;
}

static int tty_set_sid(int fd)
{
	if (ioctl(fd, TIOCSCTTY, 1)) {
		pr_perror("Can't set sid on terminal fd %d", fd);
		return -1;
	}

	return 0;
}

static int tty_set_prgp(int fd, int group)
{
	if (ioctl(fd, TIOCSPGRP, &group)) {
		pr_perror("Failed to set group %d on %d", group, fd);
		return -1;
	}
	return 0;
}

static int tty_restore_ctl_terminal(struct file_desc *d, int fd)
{
	struct tty_info *info = container_of(d, struct tty_info, d);
	int slave, ret = -1;
	char pts_name[64];

	if (!is_service_fd(fd, CTL_TTY_OFF))
		return 0;

	snprintf(pts_name, sizeof(pts_name), PTS_FMT, info->tie->pty->index);
	slave = open(pts_name, O_RDONLY);
	if (slave < 0) {
		pr_perror("Can't open %s", pts_name);
		return -1;
	}

	pr_info("Restore session %d by %d tty (index %d)\n",
		 info->tie->sid, (int)getpid(),
		 info->tie->pty->index);

	ret = tty_set_sid(slave);
	if (!ret)
		ret = tty_set_prgp(slave, info->tie->pgrp);

	close(slave);
	close(fd);

	return ret;
}

static char *tty_type(int major)
{
	static char *tty_types[] = {
		[UNIX98_PTY_SLAVE_MAJOR]	= "pts",
		[TTYAUX_MAJOR]			= "ptmx",
	};
	static char tty_unknown[]		= "unknown";

	switch (major) {
	case UNIX98_PTY_SLAVE_MAJOR:
	case TTYAUX_MAJOR:
		return tty_types[major];
	}

	return tty_unknown;
}

static bool pty_is_master(struct tty_info *info)
{
	return info->major == TTYAUX_MAJOR;
}

static bool pty_is_hung(struct tty_info *info)
{
	return info->tie->termios == NULL;
}

static bool tty_has_active_pair(struct tty_info *info)
{
	int d = pty_is_master(info) ? -1 : + 1;

	return test_bit(info->tfe->tty_info_id + d,
			tty_active_pairs);
}

static void tty_show_pty_info(char *prefix, struct tty_info *info)
{
	pr_info("%s type %s id %#x index %d (master %d sid %d pgrp %d inherit %d)\n",
		prefix, tty_type(info->major), info->tfe->id, info->tie->pty->index,
		pty_is_master(info), info->tie->sid, info->tie->pgrp, info->inherit);
}

static int restore_tty_params(int fd, struct tty_info *info)
{
	struct winsize w;
	struct termios t;

	/*
	 * It's important to zeroify termios
	 * because it contain @c_cc array which
	 * is bigger than TERMIOS_NCC. Same applies
	 * to winsize usage, we can't guarantee the
	 * structure taken from the system headers will
	 * never be extended.
	 */

	if (info->tie->termios_locked) {
		memzero(&t, sizeof(t));
		termios_copy(&t, info->tie->termios_locked);
		if (ioctl(fd, TIOCSLCKTRMIOS, &t) < 0)
			goto err;
	}

	if (info->tie->termios) {
		memzero(&t, sizeof(t));
		termios_copy(&t, info->tie->termios);
		if (ioctl(fd, TCSETS, &t) < 0)
			goto err;
	}

	if (info->tie->winsize) {
		memzero(&w, sizeof(w));
		winsize_copy(&w, info->tie->winsize);
		if (ioctl(fd, TIOCSWINSZ, &w) < 0)
			goto err;
	}

	return 0;
err:
	pr_perror("Can't set tty params on %d", info->tfe->id);
		return -1;
}

static int pty_open_slaves(struct tty_info *info)
{
	int sock = -1, fd = -1, ret = -1;
	struct fdinfo_list_entry *fle;
	struct tty_info *slave;
	char pts_name[64];

	snprintf(pts_name, sizeof(pts_name), PTS_FMT, info->tie->pty->index);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		goto err;
	}

	list_for_each_entry(slave, &info->sibling, sibling) {
		BUG_ON(pty_is_master(slave));

		fd = open(pts_name, slave->tfe->flags | O_NOCTTY);
		if (fd < 0) {
			pr_perror("Can't open slave %s", pts_name);
			goto err;
		}

		if (restore_tty_params(fd, slave))
			goto err;

		fle = file_master(&slave->d);

		pr_debug("send slave %#x fd %d connected on %s (pid %d)\n",
			 slave->tfe->id, fd, pts_name, fle->pid);

		if (send_fd_to_peer(fd, fle, sock)) {
			pr_perror("Can't send file descriptor");
			goto err;
		}

		close(fd);
		fd = -1;
	}
	ret = 0;

err:
	close_safe(&fd);
	close_safe(&sock);
	return ret;
}

static int receive_tty(struct tty_info *info)
{
	struct fdinfo_list_entry *fle;
	int fd;

	fle = file_master(&info->d);
	pr_info("\tWaiting tty fd %d (pid %d)\n", fle->fe->fd, fle->pid);

	fd = recv_fd(fle->fe->fd);
	close(fle->fe->fd);
	if (fd < 0) {
		pr_err("Can't get fd %d\n", fd);
		return -1;
	}

	if (rst_file_params(fd, info->tfe->fown, info->tfe->flags))
		close_safe(&fd);

	return fd;
}

static int pty_open_unpaired_slave(struct file_desc *d, struct tty_info *slave)
{
	int master = -1, ret = -1, fd = -1;

	/*
	 * We may have 2 cases here: the slave either need to
	 * be inherited, either it requires a fake master.
	 */

	if (likely(slave->inherit)) {
		fd = dup(get_service_fd(SELF_STDIN_OFF));
		if (fd < 0) {
			pr_perror("Can't dup SELF_STDIN_OFF");
			return -1;
		}
		pr_info("Migrated slave peer %x -> to fd %d\n",
			slave->tfe->id, fd);
	} else {
		char pts_name[64];

		snprintf(pts_name, sizeof(pts_name), PTS_FMT, slave->tie->pty->index);

		master = pty_open_ptmx_index(O_RDONLY, slave->tie->pty->index);
		if (master < 0) {
			pr_perror("Can't open fale %x (index %d)",
				  slave->tfe->id, slave->tie->pty->index);
			return -1;
		}

		unlock_pty(master);

		fd = open(pts_name, slave->tfe->flags);
		if (fd < 0) {
			pr_perror("Can't open slave %s", pts_name);
			goto err;
		}

	}

	if (restore_tty_params(fd, slave))
		goto err;

	/*
	 * If tty is migrated we need to set its group
	 * to the parent group, because signals on key
	 * presses are delivered to a group of terminal.
	 *
	 * Note, at this point the group/session should
	 * be already restored properly thus we can simply
	 * use syscalls instead of lookup via process tree.
	 */
	if (likely(slave->inherit)) {
		/*
		 * The restoration procedure only works if we're
		 * migrating not a session leader, otherwise it's
		 * not allowed to restore a group and one better to
		 * checkpoint complete process tree together with
		 * the process which keeps the master peer.
		 */
		if (root_item->sid != root_item->pid.virt) {
			pr_debug("Restore inherited group %d\n",
				 getpgid(getppid()));
			if (tty_set_prgp(fd, getpgid(getppid())))
				goto err;
		}
	}

	if (pty_open_slaves(slave))
		goto err;

	ret = fd;
	fd = -1;
err:
	close_safe(&master);
	close_safe(&fd);
	return ret;
}

static int pty_open_ptmx(struct tty_info *info)
{
	int master = -1;

	master = pty_open_ptmx_index(info->tfe->flags, info->tie->pty->index);
	if (master < 0) {
		pr_perror("Can't open %x (index %d)",
			  info->tfe->id, info->tie->pty->index);
		return -1;
	}

	unlock_pty(master);

	if (rst_file_params(master, info->tfe->fown, info->tfe->flags))
		goto err;

	if (restore_tty_params(master, info))
		goto err;

	if (info->tie->packet_mode) {
		int packet_mode = 1;

		if (ioctl(master, TIOCPKT, &packet_mode) < 0) {
			pr_perror("Can't set packed mode on %x",
				  info->tfe->id);
			goto err;
		}
	}

	if (pty_open_slaves(info))
		goto err;

	if (info->tie->locked)
		lock_pty(master);

	return master;
err:
	close_safe(&master);
	return -1;
}

static int tty_open(struct file_desc *d)
{
	struct tty_info *info = container_of(d, struct tty_info, d);

	tty_show_pty_info("open", info);

	if (!info->create)
		return receive_tty(info);

	if (!pty_is_master(info))
		return pty_open_unpaired_slave(d, info);

	return pty_open_ptmx(info);

}

static int tty_transport(FdinfoEntry *fe, struct file_desc *d)
{
	struct tty_info *info = container_of(d, struct tty_info, d);
	return !info->create;
}

static void tty_collect_fd(struct file_desc *d, struct fdinfo_list_entry *fle,
		struct rst_info *ri)
{
	struct list_head *tgt;

	/*
	 * Unix98 pty slave peers requires the master peers being
	 * opened before them
	 */

	if (pty_is_master(container_of(d, struct tty_info, d)))
		tgt = &ri->fds;
	else
		tgt = &ri->tty_slaves;

	list_add_tail(&fle->ps_list, tgt);
}

static struct file_desc_ops tty_desc_ops = {
	.type		= FD_TYPES__TTY,
	.open		= tty_open,
	.post_open	= tty_restore_ctl_terminal,
	.want_transport = tty_transport,
	.collect_fd	= tty_collect_fd,
};

static struct pstree_item *find_first_sid(int sid)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		if (item->sid == sid)
			return item;
	}

	return NULL;
}

static int tty_find_restoring_task(struct tty_info *info)
{
	struct pstree_item *item;

	/*
	 * The overall scenario is the following (note
	 * we might have corrupted image so don't believe
	 * anything).
	 *
	 * SID is present on a peer
	 * ------------------------
	 *
	 *  - if it's master peer and we have as well a slave
	 *    peer then prefer restore controlling terminal
	 *    via slave peer
	 *
	 *  - if it's master peer without slave, there must be
	 *    a SID leader who will be restoring the peer
	 *
	 *  - if it's a slave peer and no session leader found
	 *    than we need an option to inherit terminal
	 *
	 * No SID present on a peer
	 * ------------------------
	 *
	 *  - if it's a master peer than we are in good shape
	 *    and continue in a normal way, we're the peer keepers
	 *
	 *  - if it's a slave peer and no appropriate master peer
	 *    found we need an option to inherit terminal
	 *
	 * In any case if it's hungup peer, then we jump out
	 * early since it will require fake master peer and
	 * rather non-usable anyway.
	 */

	if (pty_is_hung(info)) {
		pr_debug("Hungup terminal found id %x\n", info->tfe->id);
		return 0;
	}

	if (info->tie->sid) {
		if (!pty_is_master(info)) {
			if (tty_has_active_pair(info))
				return 0;
			else
				goto shell_job;
		}

		/*
		 * Find out the task which is session leader
		 * and it can restore the controlling terminal
		 * for us.
		 */
		item = find_first_sid(info->tie->sid);
		if (item && item->pid.virt == item->sid) {
			pr_info("Set a control terminal %x to %d\n",
				info->tfe->id, info->tie->sid);
			return prepare_ctl_tty(item->pid.virt,
					       item->rst,
					       info->tfe->id);
		}

		goto notask;
	} else {
		if (pty_is_master(info))
			return 0;
		if (tty_has_active_pair(info))
			return 0;
	}

shell_job:
	if (opts.shell_job) {
		pr_info("Inherit terminal for id %x\n", info->tfe->id);
		info->inherit = true;
		return 0;
	}

notask:
	pr_err("No task found with sid %d\n", info->tie->sid);
	return -1;
}

static int tty_setup_orphan_slavery(void)
{
	struct tty_info *info, *peer, *m;

	list_for_each_entry(info, &all_ttys, list) {
		struct fdinfo_list_entry *a, *b;
		bool has_leader = false;

		if (pty_is_master(info))
			continue;

		a = file_master(&info->d);
		m = info;

		list_for_each_entry(peer, &info->sibling, sibling) {
			if (pty_is_master(peer)) {
				has_leader = true;
				break;
			}

			/*
			 * Same check as in pipes and files -- need to
			 * order slave ends so that they do not dead lock
			 * waiting for each other.
			 */
			b = file_master(&peer->d);
			if (fdinfo_rst_prio(b, a)) {
				a = b;
				m = peer;
			}
		}

		if (!has_leader) {
			m->create = true;
			pr_debug("Found orphan slave fake leader (%#x)\n",
				 m->tfe->id);
		}
	}

	return 0;
}

int tty_setup_slavery(void)
{
	struct tty_info *info, *peer, *m;

	list_for_each_entry(info, &all_ttys, list) {
		if (tty_find_restoring_task(info))
			return -1;

		peer = info;
		list_for_each_entry_safe_continue(peer, m, &all_ttys, list) {
			if (peer->tie->pty->index != info->tie->pty->index)
				continue;

			if (tty_find_restoring_task(peer))
				return -1;

			list_add(&peer->sibling, &info->sibling);
			list_del(&peer->list);
		}
	}

	/*
	 * Print out information about peers.
	 */
	list_for_each_entry(info, &all_ttys, list) {
		tty_show_pty_info("head", info);
		list_for_each_entry(peer, &info->sibling, sibling)
			tty_show_pty_info("    `- sibling", peer);
	}

	return tty_setup_orphan_slavery();
}

static int verify_termios(u32 id, TermiosEntry *e)
{
	if (e && e->n_c_cc < TERMIOS_NCC) {
		pr_err("pty ID %#x n_c_cc (%d) has wrong value\n",
		       id, (int)e->n_c_cc);
		return -1;
	}
	return 0;
}

#define term_opts_missing_cmp(p, op)		\
	(!(p)->tie->termios		op	\
	 !(p)->tie->termios_locked	op	\
	 !(p)->tie->winsize)

#define term_opts_missing_any(p)		\
	term_opts_missing_cmp(p, ||)

#define term_opts_missing_all(p)		\
	term_opts_missing_cmp(p, &&)

static int verify_info(struct tty_info *info)
{
	/*
	 * Master peer must have all parameters present,
	 * while slave peer must have either all parameters present
	 * or don't have them at all.
	 */
	if (term_opts_missing_any(info)) {
		if (pty_is_master(info)) {
			pr_err("Corrupted master peer %x\n", info->tfe->id);
			return -1;
		} else if (!term_opts_missing_all(info)) {
			pr_err("Corrupted slave peer %x\n", info->tfe->id);
			return -1;
		}
	}

	if (verify_termios(info->tfe->id, info->tie->termios_locked) ||
	    verify_termios(info->tfe->id, info->tie->termios))
		return -1;

	return 0;
}

static TtyInfoEntry *lookup_tty_info_entry(u32 id)
{
	struct tty_info_entry *e;

	list_for_each_entry(e, &all_tty_info_entries, list) {
		if (e->tie->id == id)
			return e->tie;
	}

	return NULL;
}

static int collect_one_tty_info_entry(void *obj, ProtobufCMessage *msg)
{
	struct tty_info_entry *info = obj;

	info->tie = pb_msg(msg, TtyInfoEntry);

	if (info->tie->type != TTY_TYPE__PTY) {
		pr_err("Unexpected TTY type %d (id %x)\n",
		       info->tie->type, info->tie->id);
		return -1;
	}

	if (!info->tie->pty) {
		pr_err("No PTY data found (id %x), corrupted image?\n",
		       info->tie->id);
		return -1;
	}

	INIT_LIST_HEAD(&info->list);
	list_add(&info->list, &all_tty_info_entries);

	return 0;
}

struct collect_image_info tty_info_cinfo = {
	.fd_type = CR_FD_TTY_INFO,
	.pb_type = PB_TTY_INFO,
	.priv_size = sizeof(struct tty_info_entry),
	.collect = collect_one_tty_info_entry,
	.flags = COLLECT_OPTIONAL,
};

static int collect_one_tty(void *obj, ProtobufCMessage *msg)
{
	struct tty_info *info = obj;

	info->tfe = pb_msg(msg, TtyFileEntry);

	info->tie = lookup_tty_info_entry(info->tfe->tty_info_id);
	if (!info->tie) {
		pr_err("No tty-info-id %x found on id %x\n",
		       info->tfe->tty_info_id, info->tfe->id);
		return -1;
	}

	INIT_LIST_HEAD(&info->sibling);
	info->major = major(info->tie->rdev);
	info->create = (info->major == TTYAUX_MAJOR);
	info->inherit = false;

	if (verify_info(info))
		return -1;

	/*
	 * The tty peers which have no @termios are hung up,
	 * so don't mark them as active, we create them with
	 * faked master and they are rather a rudiment which
	 * can't be used. Most likely they appear if a user has
	 * dumped program when it was closing a peer.
	 */
	if (info->tie->termios)
		tty_test_and_set(info->tfe->tty_info_id, tty_active_pairs);

	pr_info("Collected tty ID %#x\n", info->tfe->id);

	list_add(&info->list, &all_ttys);
	return file_desc_add(&info->d, info->tfe->id, &tty_desc_ops);
}

struct collect_image_info tty_cinfo = {
	.fd_type = CR_FD_TTY_FILES,
	.pb_type = PB_TTY_FILE,
	.priv_size = sizeof(struct tty_info),
	.collect = collect_one_tty,
	.flags = COLLECT_OPTIONAL,
};

/* Make sure the ttys we're dumping do belong our process tree */
int dump_verify_tty_sids(void)
{
	struct tty_dump_info *dinfo, *n;
	int ret = 0;

	/*
	 * There might be a cases where we get sid/pgid on
	 * slave peer. For example the application is running
	 * with redirection and we're migrating shell job.
	 *
	 * # ./app < /dev/zero > /dev/zero &2>1
	 *
	 * Which produce a tree like
	 *          PID   PPID  PGID  SID
	 * root     23786 23784 23786 23786 pts/0 \_ -bash
	 * root     24246 23786 24246 23786 pts/0   \_ ./app
	 *
	 * And the application goes background, then we dump
	 * it from the same shell.
	 *
	 * In this case we simply zap sid/pgid and inherit
	 * the peer from the current terminal on restore.
	 */
	list_for_each_entry_safe(dinfo, n, &all_ttys, list) {
		if (!ret && dinfo->sid) {
			struct pstree_item *item = find_first_sid(dinfo->sid);

			if (!item || item->pid.virt != dinfo->sid) {
				if (!opts.shell_job) {
					pr_err("Found dangling tty with sid %d pgid %d (%s) on peer fd %d.\n",
					       dinfo->sid, dinfo->pgrp,
					       tty_type(dinfo->major),
					       dinfo->fd);
					/*
					 * First thing people do with criu is dump smth
					 * run from shell. This is typical pitfall, warn
					 * user about it explicitly.
					 */
					pr_msg("Task attached to shell terminal. "
						"Consider using --" OPT_SHELL_JOB " option. "
						"More details on http://criu.org/Simple_loop\n");
					ret = -1;
				}
			}
		}
		xfree(dinfo);
	}

	return ret;
}

static int dump_pty_info(int lfd, u32 id, const struct fd_parms *p, int major, int index)
{
	TtyInfoEntry info		= TTY_INFO_ENTRY__INIT;
	TermiosEntry termios		= TERMIOS_ENTRY__INIT;
	TermiosEntry termios_locked	= TERMIOS_ENTRY__INIT;
	WinsizeEntry winsize		= WINSIZE_ENTRY__INIT;
	TtyPtyEntry pty			= TTY_PTY_ENTRY__INIT;
	struct parasite_tty_args *pti;
	struct tty_dump_info *dinfo;

	struct termios t;
	struct winsize w;

	int ret = -1;

	/*
	 * Make sure the structures the system provides us
	 * correlates well with protobuf templates.
	 */
	BUILD_BUG_ON(ARRAY_SIZE(t.c_cc) < TERMIOS_NCC);
	BUILD_BUG_ON(sizeof(termios.c_cc) != sizeof(void *));
	BUILD_BUG_ON((sizeof(termios.c_cc) * TERMIOS_NCC) < sizeof(t.c_cc));

	pti = parasite_dump_tty(p->ctl, p->fd);
	if (!pti)
		return -1;

	dinfo = xmalloc(sizeof(*dinfo));
	if (!dinfo)
		return -1;

	dinfo->id		= id;
	dinfo->sid		= pti->sid;
	dinfo->pgrp		= pti->pgrp;
	dinfo->fd		= p->fd;
	dinfo->major		= major;

	list_add_tail(&dinfo->list, &all_ttys);

	info.id			= id;
	info.type		= TTY_TYPE__PTY;
	info.sid		= pti->sid;
	info.pgrp		= pti->pgrp;
	info.rdev		= p->stat.st_rdev;
	info.pty		= &pty;

	info.locked		= pti->st_lock;
	info.exclusive		= pti->st_excl;
	info.packet_mode	= pti->st_pckt;

	pty.index		= index;

	/*
	 * Nothing we can do on hanging up terminal,
	 * just write out minimum information we can
	 * gather.
	 */
	if (pti->hangup)
		return pb_write_one(fdset_fd(glob_fdset, CR_FD_TTY_INFO), &info, PB_TTY_INFO);

	/*
	 * Now trace the paired/unpaired ttys. For example
	 * the task might have slave peer assigned but no
	 * master peer. Such "detached" master peers are
	 * not yet supported by our tool and better to
	 * inform a user about such situation.
	 */
	tty_test_and_set(id, tty_active_pairs);

	info.termios		= &termios;
	info.termios_locked	= &termios_locked;
	info.winsize		= &winsize;

	termios.n_c_cc		= TERMIOS_NCC;
	termios.c_cc		= xmalloc(pb_repeated_size(&termios, c_cc));

	termios_locked.n_c_cc	= TERMIOS_NCC;
	termios_locked.c_cc	= xmalloc(pb_repeated_size(&termios_locked, c_cc));

	if (!termios.c_cc || !termios_locked.c_cc)
		goto out;

	memzero(&t, sizeof(t));
	if (ioctl(lfd, TCGETS, &t) < 0) {
		pr_perror("Can't get tty params on %x", id);
		goto out;
	}
	termios_copy(&termios, &t);

	memzero(&t, sizeof(t));
	if (ioctl(lfd, TIOCGLCKTRMIOS, &t) < 0) {
		pr_perror("Can't get tty locked params on %x", id);
		goto out;
	}
	termios_copy(&termios_locked, &t);

	memzero(&w, sizeof(w));
	if (ioctl(lfd, TIOCGWINSZ, &w) < 0) {
		pr_perror("Can't get tty window params on %x", id);
		goto out;
	}
	winsize_copy(&winsize, &w);

	ret = pb_write_one(fdset_fd(glob_fdset, CR_FD_TTY_INFO), &info, PB_TTY_INFO);
out:
	xfree(termios.c_cc);
	xfree(termios_locked.c_cc);
	return ret;
}

static int dump_one_pty(int lfd, u32 id, const struct fd_parms *p)
{
	TtyFileEntry e = TTY_FILE_ENTRY__INIT;
	int ret = 0, major, index;

	pr_info("Dumping tty %d with id %#x\n", lfd, id);

	major = major(p->stat.st_rdev);
	index = parse_index(id, lfd, major);
	if (index < 0)
		return -1;

	e.id		= id;
	e.tty_info_id	= tty_gen_id(major, index);
	e.flags		= p->flags;
	e.fown		= (FownEntry *)&p->fown;

	/*
	 * FIXME
	 *
	 * Figure out how to fetch data buffered in terminal.
	 * For a while simply flush before dumping. Note
	 * we don't check for errors here since it makes
	 * no sense anyway, the buffered data is not handled
	 * properly yet.
	 *
	 * Note as well that if we have only one peer here
	 * the external end might be sending the data to us
	 * again and again while kernel buffer is not full,
	 * this might lead to endless SIGTTOU signal delivery
	 * to the dumpee, ruining checkpoint procedure.
	 *
	 * So simply do not flush the line while we dump
	 * parameters tty never was being a guaranteed delivery
	 * transport anyway.
	 */

	if (!tty_test_and_set(e.tty_info_id, tty_bitmap))
		ret = dump_pty_info(lfd, e.tty_info_id, p, major, index);

	if (!ret)
		ret = pb_write_one(fdset_fd(glob_fdset, CR_FD_TTY_FILES), &e, PB_TTY_FILE);
	return ret;
}

const struct fdtype_ops tty_dump_ops = {
	.type	= FD_TYPES__TTY,
	.dump	= dump_one_pty,
};

int tty_prep_fds(void)
{
	if (!opts.shell_job)
		return 0;

	if (!isatty(STDIN_FILENO)) {
		pr_err("Standard stream is not a terminal, aborting\n");
		return -1;
	}

	if (install_service_fd(SELF_STDIN_OFF, STDIN_FILENO) < 0) {
		pr_perror("Can't dup stdin to SELF_STDIN_OFF");
		return -1;
	}

	return 0;
}

void tty_fini_fds(void)
{
	close_service_fd(SELF_STDIN_OFF);
}
