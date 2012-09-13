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
#include "types.h"

#include "syscall.h"
#include "files.h"
#include "crtools.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "list.h"
#include "util-net.h"
#include "proc_parse.h"
#include "file-ids.h"

#include "protobuf.h"
#include "protobuf/tty.pb-c.h"

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
 * FIXME:
 *
 * - Need to find a way to restore standalone terminals, ie slaves
 *   which have no master hooked on.
 *
 * - Need to restore control terminals.
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

/*
 * /dev/ptmx is a shared resource between all tasks
 * so we need to serialize access to it.
 */
static mutex_t *tty_mutex;

int tty_prepare_shared(void)
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
		memcpy((d)->c_cc, (s)->c_cc,		\
		       min(sizeof((s)->c_cc),		\
			   sizeof((d)->c_cc)));		\
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

static int parse_index(u32 id, int lfd, int major)
{
	int index = -1;

	switch (major) {
	case TTYAUX_MAJOR:
		if (ioctl(lfd, TIOCGPTN, &index)) {
			pr_perror("Can't obtain ptmx index\n");
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

static int tty_test_and_set_index(int index)
{
	int ret;

	BUG_ON(index > (MAX_TTYS << 1));

	/* FIXME Locking! */
	ret = test_bit(index, tty_bitmap);
	if (!ret)
		set_bit(index, tty_bitmap);

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

static int try_open_pts(int index, int flags, bool report)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), PTS_FMT, index);
	fd = open(path, flags);
	if (fd < 0 && report) {
		pr_err("Can't open terminal %s\n", path);
		return -1;
	}

	return fd;
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

static int tty_get_sid(int fd)
{
	int sid, ret;

	ret = ioctl(fd, TIOCGSID, &sid);
	if (ret < 0) {
		if (errno != ENOTTY) {
			pr_perror("Can't get sid on %d", fd);
			return -1;
		}
		sid = 0;
	}
	return sid;
}

static int tty_get_pgrp(int fd)
{
	int prgp, ret;

	ret = ioctl(fd, TIOCGPGRP, &prgp);
	if (ret < 0) {
		if (errno != ENOTTY) {
			pr_perror("Can't get prgp on %d", fd);
			return -1;
		}
		prgp = 0;
	}
	return prgp;
}

static int tty_set_sid(int fd)
{
	if (ioctl(fd, TIOCSCTTY, 1)) {
		pr_perror("Can't set sid on terminal fd %d\n", fd);
		return -1;
	}

	return 0;
}

static int tty_set_prgp(int fd, int group)
{
	if (ioctl(fd, TIOCSPGRP, &group)) {
		pr_perror("Failed to set group %d on %d\n", group, fd);
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

static char *tty_type(struct tty_info *info)
{
	static char *tty_types[] = {
		[UNIX98_PTY_SLAVE_MAJOR]	= "pts",
		[TTYAUX_MAJOR]			= "ptmx",
	};
	static char tty_unknown[]		= "unknown";

	switch (info->major) {
	case UNIX98_PTY_SLAVE_MAJOR:
	case TTYAUX_MAJOR:
		return tty_types[info->major];
	}

	return tty_unknown;
}

static bool pty_is_master(struct tty_info *info)
{
	return info->major == TTYAUX_MAJOR;
}

static void tty_show_pty_info(char *prefix, struct tty_info *info)
{
	pr_info("%s type %s id %#x index %d (master %d sid %d pgrp %d)\n",
		prefix, tty_type(info), info->tfe->id, info->tie->pty->index,
		pty_is_master(info), info->tie->sid, info->tie->pgrp);
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
	 * structure taked from the system headers will
	 * never be extended.
	 */

	memzero(&t, sizeof(t));
	termios_copy(&t, info->tie->termios_locked);
	if (ioctl(fd, TIOCSLCKTRMIOS, &t) < 0)
		goto err;

	memzero(&t, sizeof(t));
	termios_copy(&t, info->tie->termios);
	if (ioctl(fd, TCSETS, &t) < 0)
		goto err;

	memzero(&w, sizeof(w));
	winsize_copy(&w, info->tie->winsize);
	if (ioctl(fd, TIOCSWINSZ, &w) < 0)
		goto err;

	return 0;
err:
	pr_perror("Can't set tty params on %d", info->tfe->id);
		return -1;
}

/*
 * Unix98 pty slave peers requires the master peers being
 * opened early, this function test if it's master pty.
 */
int tty_is_master(struct fdinfo_list_entry *le)
{
	struct tty_info *info = container_of(le->desc, struct tty_info, d);
	return pty_is_master(info);
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

		fd = open(pts_name, slave->tfe->flags);
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

	if (!pty_is_master(info))
		return receive_tty(info);

	return pty_open_ptmx(info);

}

static int tty_transport(FdinfoEntry *fe, struct file_desc *d)
{
	struct tty_info *info = container_of(d, struct tty_info, d);
	return pty_is_master(info) == false;
}

static struct file_desc_ops tty_desc_ops = {
	.type		= FD_TYPES__TTY,
	.open		= tty_open,
	.post_open	= tty_restore_ctl_terminal,
	.want_transport = tty_transport,
};

static int tty_find_restoring_task(struct tty_info *info)
{
	struct pstree_item *item;

	if (info->tie->sid == 0)
		return 0;

	pr_info("Set a control terminal to %d\n", info->tie->sid);

	for_each_pstree_item(item) {
		if (item->sid == info->tie->sid) {
			item->ctl_tty_id = info->tfe->id;
			return 0;
		}
	}

	pr_err("No task found with sid %d\n", info->tie->sid);
	return -1;
}

static int tty_setup_slavery(void)
{
	struct tty_info *info, *peer, *m;

	list_for_each_entry(info, &all_ttys, list) {
		tty_find_restoring_task(info);

		peer = info;
		list_for_each_entry_safe_continue(peer, m, &all_ttys, list) {
			if (peer->tie->pty->index != info->tie->pty->index)
				continue;

			tty_find_restoring_task(peer);

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

	return 0;
}

static int veirfy_termios(u32 id, TermiosEntry *e)
{
	if (e->n_c_cc < TERMIOS_NCC) {
		pr_err("pty ID %#x n_c_cc (%d) has wrong value\n",
		       id, (int)e->n_c_cc);
		return -1;
	}
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

	/*
	 * Verify data obtained from the image.
	 */
	if (veirfy_termios(info->tfe->id, info->tie->termios))
		return -1;
	else if (veirfy_termios(info->tfe->id, info->tie->termios_locked))
		return -1;
	else if (!pty_is_master(info) && (info->tie->sid || info->tie->pgrp)) {
		pr_err("Found sid %d pgrp %d on slave peer %x\n",
			info->tie->sid, info->tie->pgrp, info->tfe->id);
		return -1;
	}

	pr_info("Collected tty ID %#x\n", info->tfe->id);

	list_add(&info->list, &all_ttys);
	file_desc_add(&info->d, info->tfe->id, &tty_desc_ops);

	return 0;
}

int collect_tty(void)
{
	int ret;

	ret = collect_image(CR_FD_TTY_INFO, PB_TTY_INFO,
			    sizeof(struct tty_info_entry),
			    collect_one_tty_info_entry);

	ret = collect_image(CR_FD_TTY, PB_TTY,
			    sizeof(struct tty_info),
			    collect_one_tty);
	if (!ret)
		ret = tty_setup_slavery();

	return ret;
}

static int pty_get_flags(int lfd, int major, int index, TtyInfoEntry *e)
{
	int slave;

	e->locked	= false;
	e->exclusive	= false;

	/*
	 * FIXME
	 *
	 * PTYs are safe to use packet mode. While there
	 * is no way to fetch packet mode settings from
	 * the kernel, without it we see echos missing
	 * in `screen' application restore. So, just set
	 * it here for a while.
	 */
	e->packet_mode	= true;

	/*
	 * FIXME
	 *
	 * At moment we fetch only locked flag which
	 * make sense on master peer only.
	 *
	 * For exclusive and packet mode the kernel
	 * patching is needed.
	 */
	if (major != TTYAUX_MAJOR)
		return 0;

	slave = try_open_pts(index, O_RDONLY, false);
	if (slave < 0) {
		if (errno == EIO) {
			e->locked = true;
			return 0;
		} else {
			pr_err("Can't fetch flags on slave peer (index %d)\n", index);
			return -1;
		}
	}

	close(slave);
	return 0;
}

static int dump_pty_info(int lfd, u32 id, const struct fd_parms *p, int major, int index)
{
	TtyInfoEntry info		= TTY_INFO_ENTRY__INIT;
	TermiosEntry termios		= TERMIOS_ENTRY__INIT;
	TermiosEntry termios_locked	= TERMIOS_ENTRY__INIT;
	WinsizeEntry winsize		= WINSIZE_ENTRY__INIT;
	TtyPtyEntry pty			= TTY_PTY_ENTRY__INIT;

	struct termios t;
	struct winsize w;

	int ret = -1, sid, pgrp;

	sid	= tty_get_sid(lfd);
	pgrp	= tty_get_pgrp(lfd);
	if (sid < 0 || pgrp < 0)
		return -1;

	info.id			= id;
	info.type		= TTY_TYPE__PTY;
	info.sid		= sid;
	info.pgrp		= pgrp;
	info.rdev		= p->stat.st_rdev;
	info.termios		= &termios;
	info.termios_locked	= &termios_locked;
	info.winsize		= &winsize;
	info.pty		= &pty;

	pty.index		= index;

	if (pty_get_flags(lfd, major, index, &info))
		goto out;

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
	 */
	ioctl(lfd, TCFLSH, TCIOFLUSH);

	if (!tty_test_and_set_index(e.tty_info_id))
		ret = dump_pty_info(lfd, e.tty_info_id, p, major, index);

	if (!ret)
		ret = pb_write_one(fdset_fd(glob_fdset, CR_FD_TTY), &e, PB_TTY);
	return ret;
}

static const struct fdtype_ops tty_ops = {
	.type	= FD_TYPES__TTY,
	.dump	= dump_one_pty,
};

int dump_tty(struct fd_parms *p, int lfd, const struct cr_fdset *set)
{
	return do_dump_gen_file(p, lfd, &tty_ops, set);
}
