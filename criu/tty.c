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

#include "types.h"
#include "common/compiler.h"
#include "crtools.h"
#include "files.h"
#include "cr_options.h"
#include "imgset.h"
#include "servicefd.h"
#include "rst-malloc.h"
#include "log.h"
#include "common/list.h"
#include "util.h"
#include "util-pie.h"
#include "proc_parse.h"
#include "file-ids.h"
#include "files-reg.h"
#include "namespaces.h"
#include "external.h"
#include "action-scripts.h"
#include "mount.h"

#include "protobuf.h"
#include "util.h"
#include "images/tty.pb-c.h"

#include "parasite-syscall.h"
#include "parasite.h"

#include "pstree.h"
#include "fdstore.h"
#include "tty.h"

/*
 * Here are some notes about overall TTY c/r design. At moment
 * we support unix98 ptys only. Supporting legacy BSD terminals
 * is impossible without help from the kernel side -- the indices
 * of such terminals are not reported anywhere in the kernel so that
 * we can't figure out active pairs.
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
 * Note the /dev/pts/ is rather convenient agreement and internally the
 * kernel doesn't care where exactly the inodes of ptys are laying --
 * it depends on "devpts" mount point path.
 */

#undef LOG_PREFIX
#define LOG_PREFIX "tty: "

struct tty_data_entry {
	struct list_head list;
	TtyDataEntry *tde;
};

struct tty_info {
	struct list_head list;
	struct file_desc d;

	struct file_desc *reg_d;

	TtyFileEntry *tfe;
	TtyInfoEntry *tie;

	struct list_head sibling;
	struct tty_driver *driver;

	bool create;
	bool inherit;

	struct tty_info *ctl_tty;
	struct tty_info *link;
	struct tty_data_entry *tty_data;

	int fdstore_id;
};

struct tty_dump_info {
	struct list_head list;

	u32 id;
	pid_t sid;
	pid_t pgrp;
	pid_t pid_real;
	int fd;
	int mnt_id;
	struct tty_driver *driver;

	int index;
	int lfd;
	int flags;
	struct tty_dump_info *link;
	void *tty_data;
	size_t tty_data_size;
};

static bool stdin_isatty = false;
static LIST_HEAD(collected_ttys);
static LIST_HEAD(all_ttys);
static int self_stdin_fdid = -1;

/*
 * Usually an application has not that many ttys opened.
 * If this won't be enough in future we simply need to
 * change tracking mechanism to some more extendable.
 *
 * This particular bitmap requires 256 bytes of memory.
 * Pretty acceptable trade off in a sake of simplicity.
 */

#define MAX_TTYS 1088

/*
 * Custom indices should be even numbers just in case if we
 * need odds for pair numbering someday.
 */

#define MAX_PTY_INDEX  1000
#define CONSOLE_INDEX  1002
#define VT_INDEX       1004
#define CTTY_INDEX     1006
#define STTY_INDEX     1010
#define ETTY_INDEX     1012
#define ETTY_INDEX_MAX 1076
#define INDEX_ERR      (MAX_TTYS + 1)

static DECLARE_BITMAP(tty_bitmap, (MAX_TTYS << 1));
static DECLARE_BITMAP(tty_active_pairs, (MAX_TTYS << 1));

struct tty_driver {
	short type;
	short subtype;
	char *name;
	int index;
	int (*fd_get_index)(int fd, const struct fd_parms *p);
	int (*img_get_index)(struct tty_info *ti);
	int (*open)(struct tty_info *ti);
};

#define TTY_SUBTYPE_MASTER 0x0001
#define TTY_SUBTYPE_SLAVE  0x0002

static int ptm_fd_get_index(int fd, const struct fd_parms *p)
{
	int index;

	if (ioctl(fd, TIOCGPTN, &index)) {
		pr_perror("Can't obtain ptmx index");
		return INDEX_ERR;
	}

	if (index > MAX_PTY_INDEX) {
		pr_err("Index %d on ptmx is too big\n", index);
		return INDEX_ERR;
	}

	return index;
}

static int pty_get_index(struct tty_info *ti)
{
	return ti->tie->pty->index;
}

static int ext_fd_get_index(int fd, const struct fd_parms *p)
{
	static int index;

	index++;

	if (index + ETTY_INDEX > ETTY_INDEX_MAX) {
		pr_err("Too many external terminals\n");
		return INDEX_ERR;
	}

	return index + ETTY_INDEX;
}

static int pty_open_ptmx(struct tty_info *info);

static struct tty_driver ptm_driver = {
	.type = TTY_TYPE__PTY,
	.subtype = TTY_SUBTYPE_MASTER,
	.name = "ptmx",
	.fd_get_index = ptm_fd_get_index,
	.img_get_index = pty_get_index,
	.open = pty_open_ptmx,
};

static int open_simple_tty(struct tty_info *info);

static struct tty_driver console_driver = {
	.type = TTY_TYPE__CONSOLE,
	.name = "console",
	.index = CONSOLE_INDEX,
	.open = open_simple_tty,
};

static struct tty_driver ctty_driver = {
	.type = TTY_TYPE__CTTY,
	.name = "ctty",
	.index = CTTY_INDEX,
	.open = open_simple_tty,
};

static struct tty_driver vt_driver = {
	.type = TTY_TYPE__VT,
	.name = "vt",
	.index = VT_INDEX,
	.open = open_simple_tty,
};

static int open_ext_tty(struct tty_info *info);
static struct tty_driver ext_driver = {
	.type = TTY_TYPE__EXT_TTY,
	.name = "ext",
	.index = ETTY_INDEX,
	.open = open_ext_tty,
	.fd_get_index = ext_fd_get_index,
};

static struct tty_driver serial_driver = {
	.type = TTY_TYPE__SERIAL,
	.name = "serial",
	.index = STTY_INDEX,
	.open = open_simple_tty,
};

static int pts_fd_get_index(int fd, const struct fd_parms *p)
{
	int index;
	const struct fd_link *link = p->link;
	char *pos = strrchr(link->name, '/');

	if (!pos || pos == (link->name + link->len - 1)) {
		pr_err("Unexpected format on path %s\n", link->name + 1);
		return INDEX_ERR;
	}

	index = atoi(pos + 1);
	if (index > MAX_PTY_INDEX) {
		pr_err("Index %d on pts is too big\n", index);
		return INDEX_ERR;
	}

	return index;
}

static struct tty_driver pts_driver = {
	.type = TTY_TYPE__PTY,
	.subtype = TTY_SUBTYPE_SLAVE,
	.name = "pts",
	.fd_get_index = pts_fd_get_index,
	.img_get_index = pty_get_index,
	.open = pty_open_ptmx,
};

struct tty_driver *get_tty_driver(dev_t rdev, dev_t dev)
{
	int major, minor;
	char id[42];

	snprintf(id, sizeof(id), "tty[%" PRIx64 ":%" PRIx64 "]", rdev, dev);
	if (external_lookup_id(id) || inherit_fd_lookup_id(id) >= 0)
		return &ext_driver;

	major = major(rdev);
	minor = minor(rdev);

	switch (major) {
	case TTYAUX_MAJOR:
		if (minor == 2)
			return &ptm_driver;
		else if (minor == 1)
			return &console_driver;
		else if (minor == 0)
			return &ctty_driver;
		break;
	case TTY_MAJOR:
		if (minor >= MIN_NR_CONSOLES && minor <= MAX_NR_CONSOLES)
			/*
			 * Minors [MIN_NR_CONSOLES; MAX_NR_CONSOLES] stand
			 * for consoles (virtual terminals, VT in terms
			 * of kernel).
			 */
			return &vt_driver;
#ifdef __s390x__
		/*
		 * On s390 we have the following consoles:
		 * - tty3215    : ttyS0   , minor = 64, linemode console
		 * - sclp_line  : ttyS0   , minor = 64, linemode console
		 * - sclp_vt220 : ttysclp0, minor = 65, vt220 console
		 * See also "drivers/s390/char"
		 */
		else if (minor == 64 || minor == 65)
			return &vt_driver;
#endif
		/* Other minors points to UART serial ports */
		break;
	case USB_SERIAL_MAJOR:
	case LOW_DENSE_SERIAL_MAJOR:
		return &serial_driver;
	case UNIX98_PTY_MASTER_MAJOR ...(UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT - 1):
		return &ptm_driver;
	case UNIX98_PTY_SLAVE_MAJOR:
		return &pts_driver;
	}
	return NULL;
}

static inline int is_pty(struct tty_driver *driver)
{
	return driver->type == TTY_TYPE__PTY;
}

/*
 * /dev/ptmx is a shared resource between all tasks
 * so we need to serialize access to it.
 */
static mutex_t *tty_mutex;

static bool tty_is_master(struct tty_info *info);

int tty_init_restore(void)
{
	tty_mutex = shmalloc(sizeof(*tty_mutex));
	if (!tty_mutex) {
		pr_err("Can't create ptmx index mutex\n");
		return -1;
	}

	mutex_init(tty_mutex);

	return 0;
}

#define winsize_copy(d, s)                          \
	do {                                        \
		ASSIGN_MEMBER((d), (s), ws_row);    \
		ASSIGN_MEMBER((d), (s), ws_col);    \
		ASSIGN_MEMBER((d), (s), ws_xpixel); \
		ASSIGN_MEMBER((d), (s), ws_ypixel); \
	} while (0)

#define termios_copy(d, s)                                      \
	do {                                                    \
		struct termios __t;                             \
                                                                \
		memcpy((d)->c_cc, (s)->c_cc, sizeof(__t.c_cc)); \
                                                                \
		ASSIGN_MEMBER((d), (s), c_iflag);               \
		ASSIGN_MEMBER((d), (s), c_oflag);               \
		ASSIGN_MEMBER((d), (s), c_cflag);               \
		ASSIGN_MEMBER((d), (s), c_lflag);               \
		ASSIGN_MEMBER((d), (s), c_line);                \
	} while (0)

static int tty_gen_id(struct tty_driver *driver, int index)
{
	return (index << 1) + (driver->subtype == TTY_SUBTYPE_MASTER);
}

static int tty_get_index(u32 id)
{
	return id >> 1;
}

/* Make sure the active pairs do exist */
static int tty_verify_active_pairs(void)
{
	unsigned long i, unpaired_slaves = 0;

	for_each_bit(i, tty_active_pairs) {
		if ((i % 2) == 0) {
			if (test_bit(i + 1, tty_active_pairs)) {
				i++;
				continue;
			}

			if (!opts.shell_job && !opts.orphan_pts_master) {
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

static int tty_test_and_set(int bit, unsigned long *bitmap)
{
	int ret;

	ret = test_bit(bit, bitmap);
	if (!ret)
		set_bit(bit, bitmap);
	return ret;
}

/*
 * Generate a regular file object in case if such is missed
 * in the image file, ie obsolete interface has been used on
 * checkpoint.
 */
static struct file_desc *pty_alloc_reg(struct tty_info *info, bool add)
{
	TtyFileEntry *tfe = info->tfe;
	const size_t namelen = 64;
	struct reg_file_info *r;
	static struct file_desc_ops noops = {};

	r = xzalloc(sizeof(*r) + sizeof(*r->rfe) + namelen);
	if (!r)
		return NULL;

	r->rfe = (void *)r + sizeof(*r);
	reg_file_entry__init(r->rfe);

	r->rfe->name = (void *)r + sizeof(*r) + sizeof(*r->rfe);
	if (tty_is_master(info))
		strcpy(r->rfe->name, "/dev/ptmx");
	else
		snprintf(r->rfe->name, namelen, "/dev/pts/%u", info->tie->pty->index);

	if (add)
		file_desc_add(&r->d, tfe->id, &noops);
	else
		file_desc_init(&r->d, tfe->id, &noops);

	r->rfe->id = tfe->id;
	r->rfe->flags = tfe->flags;
	r->rfe->fown = tfe->fown;
	r->path = &r->rfe->name[1];

	return &r->d;
}

/*
 * In case if we need to open a fake pty (for example
 * a master peer which were deleted at checkpoint moment,
 * or open a slave peer when restoring control terminal)
 * we need to create a new reg-file object taking @info
 * as a template. Here is a trick though: the @info might
 * represent master peer while we need to allocate a slave
 * one and the reverse. For such case taking path from the
 * @info as a template we generate that named 'inverted-path'.
 *
 * For example if the master peer was /dev/pts/ptmx with index 1,
 * the inverted path is /dev/pts/1, for inverted slaves it's simpler
 * we just add 'ptmx' postfix.
 */
static struct reg_file_info *pty_alloc_fake_reg(struct tty_info *info, int subtype)
{
	struct reg_file_info *new, *orig;
	struct file_desc *fake_desc;

	pr_debug("Allocating fake descriptor for %#x (reg_d %p)\n", info->tfe->id, info->reg_d);

	BUG_ON(!info->reg_d);
	BUG_ON(!is_pty(info->driver));

	fake_desc = pty_alloc_reg(info, false);
	if (!fake_desc)
		return NULL;

	orig = container_of(info->reg_d, struct reg_file_info, d);
	new = container_of(fake_desc, struct reg_file_info, d);

	if ((subtype == TTY_SUBTYPE_MASTER && tty_is_master(info)) ||
	    (subtype == TTY_SUBTYPE_SLAVE && !tty_is_master(info))) {
		new->path = xstrdup(orig->path);
		new->rfe->name = &new->path[1];
	} else {
		char *pos = strrchr(orig->rfe->name, '/');
		size_t len = strlen(orig->rfe->name) + 1;
		size_t slash_at = pos - orig->rfe->name;
		char *inverted_path = xmalloc(len + 32);

		BUG_ON(!pos || !inverted_path);

		memcpy(inverted_path, orig->rfe->name, slash_at + 1);
		if (subtype == TTY_SUBTYPE_MASTER) {
			inverted_path[slash_at + 1] = '\0';
			strcat(inverted_path, "ptmx");
		} else {
			if (slash_at >= 3 && strncmp(&inverted_path[slash_at - 3], "pts", 3))
				snprintf(&inverted_path[slash_at + 1], 10, "pts/%u", info->tie->pty->index);
			else
				snprintf(&inverted_path[slash_at + 1], 10, "%u", info->tie->pty->index);
		}

		new->rfe->name = inverted_path;
		new->path = &inverted_path[1];
	}

	return new;
}

#define pty_alloc_fake_master(info) pty_alloc_fake_reg(info, TTY_SUBTYPE_MASTER)
#define pty_alloc_fake_slave(info)  pty_alloc_fake_reg(info, TTY_SUBTYPE_SLAVE)

static void pty_free_fake_reg(struct reg_file_info **r)
{
	if (*r) {
		xfree((*r)->rfe->name);
		xfree((*r));
		*r = NULL;
	}
}

static int do_open_tty_reg(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	int fd;

	fd = do_open_reg_noseek_flags(ns_root_fd, rfi, arg);
	if (fd >= 0) {
		/*
		 * Peers might have different modes set
		 * after creation before we've dumped
		 * them. So simply setup mode from image
		 * the regular file engine will check
		 * for this, so if we fail here it
		 * gonna be caught anyway.
		 */
		if (rfi->rfe->has_mode)
			fchmod(fd, rfi->rfe->mode);
	}

	return fd;
}

static int open_tty_reg(void *arg, int flags)
{
	struct file_desc *reg_d = arg;
	/*
	 * Never set as a control terminal automatically, all
	 * ctty magic happens only in tty_set_sid().
	 */
	flags |= O_NOCTTY;
	return open_path(reg_d, do_open_tty_reg, &flags);
}

static char *path_from_reg(struct file_desc *d)
{
	struct reg_file_info *rfi = container_of(d, struct reg_file_info, d);
	return rfi->path;
}

static int __pty_open_ptmx_index(int index, int flags, int (*cb)(void *arg, int flags), void *arg, char *path)
{
	int fds[32], i, ret = -1, cur_idx;

	memset(fds, 0xff, sizeof(fds));

	mutex_lock(tty_mutex);

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		fds[i] = cb(arg, flags);
		if (fds[i] < 0) {
			pr_err("Can't open %s\n", path);
			break;
		}

		if (ioctl(fds[i], TIOCGPTN, &cur_idx)) {
			pr_perror("Can't obtain current index on %s", path);
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

		pr_err("Unable to open %s with specified index %d\n", path, index);
		break;
	}

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	mutex_unlock(tty_mutex);

	return ret;
}

static int pty_open_ptmx_index(struct file_desc *d, struct tty_info *info, int flags)
{
	if (info->fdstore_id >= 0)
		return fdstore_get(info->fdstore_id);

	return __pty_open_ptmx_index(info->tie->pty->index, flags, open_tty_reg, d, path_from_reg(d));
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

static int tty_restore_ctl_terminal(struct file_desc *d)
{
	struct tty_info *info = container_of(d, struct tty_info, d);
	struct tty_driver *driver = info->driver;
	struct reg_file_info *fake = NULL;
	struct file_desc *slave_d;
	int slave = -1, ret = -1, index = -1;

	if (driver->type == TTY_TYPE__EXT_TTY) {
		slave = -1;
		if (!inherited_fd(&info->d, &slave) && slave < 0)
			return -1;
		goto out;
	}
	if (driver->img_get_index)
		index = driver->img_get_index(info);
	else
		index = driver->index;

	if (is_pty(info->driver) && tty_is_master(info)) {
		fake = pty_alloc_fake_slave(info);
		if (!fake)
			goto err;

		slave_d = &fake->d;
	} else
		slave_d = info->reg_d;

	slave = open_tty_reg(slave_d, O_RDONLY);
	if (slave < 0) {
		pr_err("Can't open slave tty %s\n", path_from_reg(slave_d));
		goto err;
	}

out:
	pr_info("Restore session %d by %d tty (index %d)\n", info->tie->sid, (int)getpid(), index);

	ret = tty_set_sid(slave);
	if (!ret)
		ret = tty_set_prgp(slave, info->tie->pgrp);

	close(slave);
err:
	pty_free_fake_reg(&fake);
	return ret ? -1 : 0;
}

static bool __tty_is_master(struct tty_driver *driver)
{
	if (driver->subtype == TTY_SUBTYPE_MASTER)
		return true;

	switch (driver->type) {
	case TTY_TYPE__CONSOLE:
	case TTY_TYPE__CTTY:
		return true;
	case TTY_TYPE__SERIAL:
	case TTY_TYPE__VT:
		if (!opts.shell_job)
			return true;
		break;
	case TTY_TYPE__EXT_TTY:
		return true;
	}

	return false;
}

static bool tty_is_master(struct tty_info *info)
{
	return __tty_is_master(info->driver);
}

static bool tty_is_hung(struct tty_info *info)
{
	return info->tie->termios == NULL;
}

static bool tty_has_active_pair(struct tty_info *info)
{
	int d = tty_is_master(info) ? -1 : +1;

	return test_bit(info->tfe->tty_info_id + d, tty_active_pairs);
}

static void tty_show_pty_info(char *prefix, struct tty_info *info)
{
	int index = -1;
	struct tty_driver *driver = info->driver;

	if (driver->img_get_index)
		index = driver->img_get_index(info);
	else
		index = driver->index;

	pr_info("%s driver %s id %#x index %d (master %d sid %d pgrp %d inherit %d)\n", prefix, info->driver->name,
		info->tfe->id, index, tty_is_master(info), info->tie->sid, info->tie->pgrp, info->inherit);
}

struct tty_parms {
	int tty_id;
	unsigned has;
#define HAS_TERMIOS_L 0x1
#define HAS_TERMIOS   0x2
#define HAS_WINS      0x4
	struct termios tl;
	struct termios t;
	struct winsize w;
};

static int do_restore_tty_parms(void *arg, int fd, pid_t pid)
{
	struct tty_parms *p = arg;

	/*
	 * Only locked termios need CAP_SYS_ADMIN, but we
	 * restore them all here, since the regular tremios
	 * restore is affected by locked and thus we would
	 * have to do synchronous usernsd call which is not
	 * nice.
	 *
	 * Window size is restored here as it might depend
	 * on termios too. Just to be on the safe side.
	 */

	if ((p->has & HAS_TERMIOS_L) && ioctl(fd, TIOCSLCKTRMIOS, &p->tl) < 0)
		goto err;

	if ((p->has & HAS_TERMIOS) && ioctl(fd, TCSETS, &p->t) < 0)
		goto err;

	if ((p->has & HAS_WINS) && ioctl(fd, TIOCSWINSZ, &p->w) < 0)
		goto err;

	return 0;

err:
	pr_perror("Can't set tty params on %#x", p->tty_id);
	return -1;
}

static int restore_tty_params(int fd, struct tty_info *info)
{
	struct tty_parms p;

	/*
	 * It's important to zeroify termios
	 * because it contain @c_cc array which
	 * is bigger than TERMIOS_NCC. Same applies
	 * to winsize usage, we can't guarantee the
	 * structure taken from the system headers will
	 * never be extended.
	 */

	p.has = 0;
	p.tty_id = info->tfe->id;

	if (info->tie->termios_locked) {
		memzero(&p.tl, sizeof(p.tl));
		p.has |= HAS_TERMIOS_L;
		termios_copy(&p.tl, info->tie->termios_locked);
	}

	if (info->tie->termios) {
		memzero(&p.t, sizeof(p.t));
		p.has |= HAS_TERMIOS;
		termios_copy(&p.t, info->tie->termios);
	}

	if (info->tie->winsize) {
		memzero(&p.w, sizeof(p.w));
		p.has |= HAS_WINS;
		winsize_copy(&p.w, info->tie->winsize);
	}

	if (info->tie->has_uid && info->tie->has_gid) {
		if (cr_fchown(fd, info->tie->uid, info->tie->gid)) {
			pr_perror("Can't setup uid %d gid %d on %#x", (int)info->tie->uid, (int)info->tie->gid,
				  info->tfe->id);
			return -1;
		}
	}

	return userns_call(do_restore_tty_parms, 0, &p, sizeof(p), fd);
}

/*
 * When we restore queued data we don't exit if error happened:
 * the terminals never was a transport with guaranteed delivery,
 * it's up to application which uses it to guaratee the data
 * integrity.
 */
static void pty_restore_queued_data(struct tty_info *info, int fd)
{
	if (info && info->tty_data) {
		ProtobufCBinaryData bd = info->tty_data->tde->data;
		int retval;

		pr_debug("restore queued data on %#x (%zu bytes)\n", info->tfe->id, (size_t)bd.len);

		retval = write(fd, bd.data, bd.len);
		if (retval != bd.len)
			pr_err("Restored %d bytes while %zu expected\n", retval, (size_t)bd.len);
	}
}

static int pty_open_slaves(struct tty_info *info)
{
	int fd = -1, ret = -1;
	struct tty_info *slave;

	list_for_each_entry(slave, &info->sibling, sibling) {
		BUG_ON(tty_is_master(slave));

		fd = open_tty_reg(slave->reg_d, slave->tfe->flags);
		if (fd < 0) {
			pr_err("Can't open slave tty %s\n", path_from_reg(slave->reg_d));
			goto err;
		}

		if (restore_tty_params(fd, slave))
			goto err;

		pr_debug("send slave %#x fd %d connected on %s\n", slave->tfe->id, fd, path_from_reg(slave->reg_d));

		if (send_desc_to_peer(fd, &slave->d)) {
			pr_err("Can't send file descriptor\n");
			goto err;
		}

		pty_restore_queued_data(slave->link, fd);
		close(fd);
		fd = -1;
	}
	ret = 0;

err:
	close_safe(&fd);
	return ret;
}

static int receive_tty(struct tty_info *info, int *new_fd)
{
	int fd, ret;

	ret = recv_desc_from_peer(&info->d, &fd);
	if (ret != 0) {
		if (ret != 1)
			pr_err("Can't get fd %d\n", fd);
		return ret;
	}

	if (rst_file_params(fd, info->tfe->fown, info->tfe->flags) < 0) {
		close_safe(&fd);
		return -1;
	}

	*new_fd = fd;
	return 0;
}

static int pty_open_unpaired_slave(struct file_desc *d, struct tty_info *slave)
{
	struct reg_file_info *fake = NULL;
	int master = -1, ret = -1, fd = -1;

	/*
	 * We may have 2 cases here: the slave either need to
	 * be inherited, either it requires a fake master.
	 */

	if (likely(slave->inherit)) {
		if (opts.orphan_pts_master) {
			fake = pty_alloc_fake_master(slave);
			if (!fake)
				goto err;
			master = pty_open_ptmx_index(&fake->d, slave, O_RDWR);
			if (master < 0) {
				pr_err("Can't open master pty %x (index %d)\n", slave->tfe->id, slave->tie->pty->index);
				goto err;
			}

			if (unlock_pty(master))
				goto err;

			if (opts.orphan_pts_master && rpc_send_fd(ACT_ORPHAN_PTS_MASTER, master) == 0) {
				fd = open_tty_reg(slave->reg_d, slave->tfe->flags);
				if (fd < 0) {
					pr_err("Can't open slave pty %s\n", path_from_reg(slave->reg_d));
					goto err;
				}

				goto out;
			}
		}

		if (!stdin_isatty) {
			pr_err("Don't have tty to inherit session from, aborting\n");
			return -1;
		}

		fd = fdstore_get(self_stdin_fdid);
		if (fd < 0) {
			pr_err("Can't get self_stdin_fdid\n");
			return -1;
		}

		pr_info("Migrated slave peer %#x -> to fd %d\n", slave->tfe->id, fd);
	} else {
		fake = pty_alloc_fake_master(slave);
		if (!fake)
			goto err;
		master = pty_open_ptmx_index(&fake->d, slave, O_RDONLY);
		if (master < 0) {
			pr_err("Can't open master pty %#x (index %d)\n", slave->tfe->id, slave->tie->pty->index);
			goto err;
		}

		if (unlock_pty(master))
			goto err;

		fd = open_tty_reg(slave->reg_d, slave->tfe->flags);
		if (fd < 0) {
			pr_err("Can't open slave pty %s\n", path_from_reg(slave->reg_d));
			goto err;
		}
	}

out:
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
	if (slave->inherit && opts.shell_job) {
		/*
		 * The restoration procedure only works if we're
		 * migrating not a session leader, otherwise it's
		 * not allowed to restore a group and one better to
		 * checkpoint complete process tree together with
		 * the process which keeps the master peer.
		 */
		if (root_item->sid != vpid(root_item)) {
			if (root_item->pgid == vpid(root_item)) {
				if (tty_set_prgp(fd, root_item->pgid))
					goto err;
			} else {
				pr_debug("Restore inherited group %d\n", getpgid(getppid()));
				if (tty_set_prgp(fd, getpgid(getppid())))
					goto err;
			}
		}
	}

	if (pty_open_slaves(slave))
		goto err;

	ret = fd;
	fd = -1;
err:
	close_safe(&master);
	close_safe(&fd);
	pty_free_fake_reg(&fake);
	return ret;
}

static int pty_open_ptmx(struct tty_info *info)
{
	int master = -1;

	master = pty_open_ptmx_index(info->reg_d, info, info->tfe->flags);
	if (master < 0) {
		pr_err("Can't open master pty %#x (index %d)\n", info->tfe->id, info->tie->pty->index);
		return -1;
	}

	if (unlock_pty(master))
		goto err;

	if (restore_tty_params(master, info))
		goto err;

	if (info->tie->packet_mode) {
		int packet_mode = 1;

		if (ioctl(master, TIOCPKT, &packet_mode) < 0) {
			pr_perror("Can't set packed mode on %#x", info->tfe->id);
			goto err;
		}
	}

	if (pty_open_slaves(info))
		goto err;

	pty_restore_queued_data(info->link, master);

	if (info->tie->locked)
		lock_pty(master);

	return master;
err:
	close_safe(&master);
	return -1;
}

static int open_simple_tty(struct tty_info *info)
{
	int fd = -1;

	fd = open_tty_reg(info->reg_d, info->tfe->flags);
	if (fd < 0) {
		pr_err("Can't open tty %s %#x\n", info->driver->name, info->tfe->id);
		return -1;
	}

	if (restore_tty_params(fd, info))
		goto err;

	return fd;
err:
	close_safe(&fd);
	return -1;
}

static int open_ext_tty(struct tty_info *info)
{
	int fd = -1;

	if (!inherited_fd(&info->d, &fd) && fd < 0)
		return -1;

	if (restore_tty_params(fd, info)) {
		close(fd);
		return -1;
	}

	return fd;
}

static bool tty_deps_restored(struct tty_info *info)
{
	struct list_head *list = &rsti(current)->fds;
	struct fdinfo_list_entry *fle;
	struct tty_info *tmp;

	if (info->driver->type == TTY_TYPE__CTTY) {
		list_for_each_entry(fle, list, ps_list) {
			if (fle->desc->ops->type != FD_TYPES__TTY || fle->desc == &info->d)
				continue;

			/* ctty needs all others are restored */
			if (fle->stage != FLE_RESTORED)
				return false;
		}
	} else if (!tty_is_master(info)) {
		list_for_each_entry(fle, list, ps_list) {
			if (fle->desc->ops->type != FD_TYPES__TTY || fle->desc == &info->d)
				continue;
			tmp = container_of(fle->desc, struct tty_info, d);

			/* slaves wait for masters except ctty */
			if (tmp->driver->type == TTY_TYPE__CTTY || !tty_is_master(tmp))
				continue;
			if (fle->stage != FLE_RESTORED)
				return false;
		}
	}
	return true;
}

static int tty_open(struct file_desc *d, int *new_fd)
{
	struct tty_info *info = container_of(d, struct tty_info, d);
	int ret;

	tty_show_pty_info("open", info);

	if (!info->create)
		return receive_tty(info, new_fd);

	if (!tty_deps_restored(info))
		return 1;

	if (is_pty(info->driver) && !tty_is_master(info))
		ret = pty_open_unpaired_slave(d, info);
	else
		ret = info->driver->open(info);
	if (ret < 0)
		return -1;
	*new_fd = ret;
	return 0;
}

static char *tty_d_name(struct file_desc *d, char *buf, size_t s)
{
	struct tty_info *info = container_of(d, struct tty_info, d);

	snprintf(buf, s, "tty[%x:%x]", info->tie->rdev, info->tie->dev);

	return buf;
}

static struct file_desc_ops tty_desc_ops = {
	.type = FD_TYPES__TTY,
	.open = tty_open,
	.name = tty_d_name,
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

static int add_fake_fle(struct pstree_item *item, u32 desc_id)
{
	FdinfoEntry *e;

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;

	fdinfo_entry__init(e);

	e->id = desc_id;
	e->fd = find_unused_fd(item, -1);
	e->type = FD_TYPES__TTY;

	if (collect_fd(vpid(item), e, rsti(item), true)) {
		xfree(e);
		return -1;
	}

	return e->fd;
}

struct ctl_tty {
	struct file_desc desc;
	struct fdinfo_list_entry *real_tty;
};

static int ctl_tty_open(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle;
	int ret;

	fle = container_of(d, struct ctl_tty, desc)->real_tty;
	if (fle->stage != FLE_RESTORED)
		return 1;

	ret = tty_restore_ctl_terminal(fle->desc);
	if (!ret) {
		/*
		 * Generic engine expects we return a new_fd.
		 * Return this one just to return something.
		 */
		*new_fd = dup(fle->fe->fd);
		if (*new_fd < 0) {
			pr_perror("dup() failed");
			ret = -1;
		} else
			ret = 0;
	}
	return ret;
}

/*
 * This is a fake type to handle ctl tty. The problem
 * is sometimes we need to do tty_set_sid() from slave
 * fle, while generic file engine allows to call open
 * method for file masters only. So, this type allows
 * to add fake masters, which will call open for slave
 * fles of type FD_TYPES__TTY indirectly.
 */
static struct file_desc_ops ctl_tty_desc_ops = {
	.type = FD_TYPES__CTL_TTY,
	.open = ctl_tty_open,
};

static int prepare_ctl_tty(struct pstree_item *item, u32 ctl_tty_id)
{
	struct fdinfo_list_entry *fle;
	struct ctl_tty *ctl_tty;
	FdinfoEntry *e;
	int fd;

	if (!ctl_tty_id)
		return 0;

	pr_info("Requesting for ctl tty %#x into service fd\n", ctl_tty_id);

	/* Add a fake fle to make generic engine deliver real tty desc to task */
	fd = add_fake_fle(item, ctl_tty_id);
	if (fd < 0)
		return -1;

	fle = find_used_fd(item, fd);
	BUG_ON(!fle);
	/*
	 * Add a fake ctl_tty depending on the above fake fle, which will
	 * actually restore the session.
	 */
	ctl_tty = xmalloc(sizeof(*ctl_tty));
	e = xmalloc(sizeof(*e));

	if (!ctl_tty || !e)
		goto err;

	ctl_tty->real_tty = fle;

	/*
	 * Use the same ctl_tty_id id for ctl_tty as it's unique among
	 * FD_TYPES__CTL_TTY (as it's unique for FD_TYPES__TTY type).
	 */
	file_desc_add(&ctl_tty->desc, ctl_tty_id, &ctl_tty_desc_ops);

	fdinfo_entry__init(e);

	e->id = ctl_tty_id;
	e->fd = find_unused_fd(item, -1);
	e->type = FD_TYPES__CTL_TTY;

	if (collect_fd(vpid(item), e, rsti(item), true))
		goto err;

	return 0;
err:
	xfree(ctl_tty);
	xfree(e);
	return -1;
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

	if (tty_is_hung(info)) {
		pr_debug("Hungup terminal found id %#x\n", info->tfe->id);
		return 0;
	}

	/*
	 * Current tty should be skipped here: the
	 * underlied _real_ pty (or anything else
	 * driver in future) should restore the
	 * session.
	 */
	if (info->driver->type == TTY_TYPE__CTTY)
		return 0;

	if (info->tie->sid) {
		if (!tty_is_master(info)) {
			if (tty_has_active_pair(info))
				return 0;
			else if (!opts.orphan_pts_master)
				goto shell_job;
			else
				info->inherit = true;
		}

		/*
		 * Restoring via leader only. All files
		 * opened over same real tty get propagated
		 * automatically by kernel itself.
		 */
		if (info->ctl_tty != info)
			return 0;

		/*
		 * Find out the task which is session leader
		 * and it can restore the controlling terminal
		 * for us.
		 */
		item = find_first_sid(info->tie->sid);
		if (item && vpid(item) == item->sid) {
			pr_info("Set a control terminal %#x to %d\n", info->tfe->id, info->tie->sid);
			return prepare_ctl_tty(item, info->tfe->id);
		}

		goto notask;
	} else {
		if (tty_is_master(info))
			return 0;
		if (tty_has_active_pair(info))
			return 0;
	}

shell_job:
	if (opts.shell_job) {
		pr_info("Inherit terminal for id %#x\n", info->tfe->id);
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

		if (tty_is_master(info))
			continue;

		a = file_master(&info->d);
		m = info;

		list_for_each_entry(peer, &info->sibling, sibling) {
			if (tty_is_master(peer)) {
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
			pr_debug("Found orphan slave fake leader (%#x)\n", m->tfe->id);
		}
	}

	return 0;
}

static int tty_setup_slavery(void)
{
	struct tty_info *info, *peer, *m;

	/*
	 * Setup links for PTY terminal pairs by
	 * their indices, queued data already bound
	 * to them by data ids.
	 */
	list_for_each_entry(info, &all_ttys, list) {
		if (!is_pty(info->driver) || info->link)
			continue;
		peer = info;
		list_for_each_entry_continue(peer, &all_ttys, list) {
			if (!is_pty(peer->driver) || peer->link)
				continue;
			if (peer->tie->pty->index == info->tie->pty->index) {
				info->link = peer;
				peer->link = info;

				pr_debug("Link PTYs (%#x)\n", info->tfe->id);
				break;
			}
		}
	}

	/*
	 * The image may carry several terminals opened
	 * belonging to the same session, so choose the
	 * leader which gonna be setting up the controlling
	 * terminal.
	 */
	list_for_each_entry(info, &all_ttys, list) {
		if (!info->tie->sid || info->ctl_tty || info->driver->type == TTY_TYPE__CTTY)
			continue;

		if (!tty_is_master(info) && info->link)
			continue;

		info->ctl_tty = info;
		pr_debug("ctl tty leader %#x\n", info->tfe->id);
		peer = info;
		list_for_each_entry_safe_continue(peer, m, &all_ttys, list) {
			if (!peer->tie->sid || peer->ctl_tty || peer->driver->type == TTY_TYPE__CTTY)
				continue;
			if (peer->tie->sid == info->tie->sid) {
				pr_debug(" `- slave %#x\n", peer->tfe->id);
				peer->ctl_tty = info;
			}
		}
	}

	list_for_each_entry(info, &all_ttys, list) {
		if (tty_find_restoring_task(info))
			return -1;
		if (!is_pty(info->driver))
			continue;

		peer = info;
		list_for_each_entry_safe_continue(peer, m, &all_ttys, list) {
			if (!is_pty(peer->driver))
				continue;
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
		pr_err("pty ID %#x n_c_cc (%d) has wrong value\n", id, (int)e->n_c_cc);
		return -1;
	}
	return 0;
}

#define term_opts_missing_cmp(tie, op) (!(tie)->termios op !(tie)->termios_locked op !(tie)->winsize)

#define term_opts_missing_any(p) term_opts_missing_cmp(p, ||)

#define term_opts_missing_all(p) term_opts_missing_cmp(p, &&)

static int verify_info(TtyInfoEntry *tie, struct tty_driver *driver)
{
	/*
	 * Master peer must have all parameters present,
	 * while slave peer must have either all parameters present
	 * or don't have them at all.
	 */
	if (term_opts_missing_any(tie)) {
		if (__tty_is_master(driver)) {
			pr_err("Corrupted master peer %#x\n", tie->id);
			return -1;
		} else if (!term_opts_missing_all(tie)) {
			pr_err("Corrupted slave peer %#x\n", tie->id);
			return -1;
		}
	}

	if (verify_termios(tie->id, tie->termios_locked) || verify_termios(tie->id, tie->termios))
		return -1;

	if (tie->termios && tie->id > (MAX_TTYS << 1))
		return -1;

	return 0;
}

static int tty_info_setup(struct tty_info *info);

static int collect_one_tty_info_entry(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct tty_info *info, *n;
	TtyInfoEntry *tie;
	struct tty_driver *driver;

	tie = pb_msg(msg, TtyInfoEntry);

	switch (tie->type) {
	case TTY_TYPE__PTY:
		if (!tie->pty) {
			pr_err("No PTY data found (id %#x), corrupted image?\n", tie->id);
			return -1;
		}
		break;
	case TTY_TYPE__CTTY:
	case TTY_TYPE__CONSOLE:
	case TTY_TYPE__SERIAL:
	case TTY_TYPE__VT:
	case TTY_TYPE__EXT_TTY:
		if (tie->pty) {
			pr_err("PTY data found (id %#x), corrupted image?\n", tie->id);
			return -1;
		}
		break;
	default:
		pr_err("Unexpected TTY type %d (id %#x)\n", tie->type, tie->id);
		return -1;
	}

	driver = get_tty_driver(tie->rdev, tie->dev);
	if (driver == NULL) {
		pr_err("Unable to find a tty driver (rdev %#x dev %#x)\n", tie->rdev, tie->dev);
		return -1;
	}

	if (verify_info(tie, driver))
		return -1;

	list_for_each_entry_safe(info, n, &collected_ttys, list) {
		if (info->tfe->tty_info_id != tie->id)
			continue;

		info->tie = tie;
		info->driver = driver;
		list_move_tail(&info->list, &all_ttys);

		if (tty_info_setup(info))
			return -1;
	}

	/*
	 * The tty peers which have no @termios are hung up,
	 * so don't mark them as active, we create them with
	 * faked master and they are rather a rudiment which
	 * can't be used. Most likely they appear if a user has
	 * dumped program when it was closing a peer.
	 */
	if (is_pty(driver) && tie->termios)
		tty_test_and_set(tie->id, tty_active_pairs);

	return 0;
}

struct collect_image_info tty_info_cinfo = {
	.fd_type = CR_FD_TTY_INFO,
	.pb_type = PB_TTY_INFO,
	.collect = collect_one_tty_info_entry,
	.flags = COLLECT_NOFREE,
};

static int prep_tty_restore_cb(struct pprep_head *ph)
{
	if (!list_empty(&collected_ttys)) {
		pr_err("Not all TTYs got its infos\n");
		return -1;
	}
	if (tty_verify_active_pairs())
		return -1;
	if (tty_setup_slavery())
		return -1;
	return 0;
}

static MAKE_PPREP_HEAD(prep_tty_restore);

static int collect_one_tty(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct tty_info *info = obj;

	info->tfe = pb_msg(msg, TtyFileEntry);
	list_add_tail(&info->list, &collected_ttys);

	return 0;
}

static int tty_info_setup(struct tty_info *info)
{
	INIT_LIST_HEAD(&info->sibling);
	info->create = tty_is_master(info);
	info->inherit = false;
	info->ctl_tty = NULL;
	info->tty_data = NULL;
	info->link = NULL;

	/*
	 * The image might have no reg file record in old CRIU, so
	 * lets don't fail for a while. After a couple of releases
	 * simply require the record to present.
	 *
	 * Note for external ttys it's fine to not have any
	 * reg file rectord because they are inherited from
	 * command line on restore.
	 */
	info->reg_d = try_collect_special_file(info->tfe->has_regf_id ? info->tfe->regf_id : info->tfe->id, 1);
	if (!info->reg_d) {
		if (info->driver->type != TTY_TYPE__EXT_TTY) {
			if (!deprecated_ok("TTY w/o regfile"))
				return -1;

			if (is_pty(info->driver)) {
				info->reg_d = pty_alloc_reg(info, true);
				if (!info->reg_d) {
					pr_err("Can't generate new reg descriptor for id %#x\n", info->tfe->id);
					return -1;
				}
			} else {
				pr_err("No reg_d descriptor for id %#x\n", info->tfe->id);
				return -1;
			}
		}
	}

	pr_info("Collected tty ID %#x (%s)\n", info->tfe->id, info->driver->name);

	add_post_prepare_cb_once(&prep_tty_restore);

	info->fdstore_id = -1;
	return file_desc_add(&info->d, info->tfe->id, &tty_desc_ops);
}

struct collect_image_info tty_cinfo = {
	.fd_type = CR_FD_TTY_FILES,
	.pb_type = PB_TTY_FILE,
	.priv_size = sizeof(struct tty_info),
	.collect = collect_one_tty,
};

static int collect_one_tty_data(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct tty_data_entry *tdo = obj;
	struct tty_info *info;

	tdo->tde = pb_msg(msg, TtyDataEntry);
	pr_debug("Collected data for id %#x (size %zu bytes)\n", tdo->tde->tty_id, (size_t)tdo->tde->data.len);

	list_for_each_entry(info, &all_ttys, list) {
		if (tdo->tde->tty_id == info->tie->id) {
			info->tty_data = tdo;
			return 0;
		}
	}

	pr_err("No tty found to queued data on id %#x\n", tdo->tde->tty_id);
	return -ENOENT;
}

struct collect_image_info tty_cdata = {
	.fd_type = CR_FD_TTY_DATA,
	.pb_type = PB_TTY_DATA,
	.priv_size = sizeof(struct tty_data_entry),
	.collect = collect_one_tty_data,
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

			if (!item || vpid(item) != dinfo->sid) {
				if (!opts.shell_job) {
					pr_err("Found dangling tty with sid %d pgid %d (%s) on peer fd %d.\n",
					       dinfo->sid, dinfo->pgrp, dinfo->driver->name, dinfo->fd);
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
	}

	return ret;
}

static int dump_tty_info(int lfd, u32 id, const struct fd_parms *p, struct tty_driver *driver, int index)
{
	TtyInfoEntry info = TTY_INFO_ENTRY__INIT;
	TermiosEntry termios = TERMIOS_ENTRY__INIT;
	TermiosEntry termios_locked = TERMIOS_ENTRY__INIT;
	WinsizeEntry winsize = WINSIZE_ENTRY__INIT;
	TtyPtyEntry pty = TTY_PTY_ENTRY__INIT;
	struct parasite_tty_args *pti;
	struct tty_dump_info *dinfo;

	struct termios t;
	struct winsize w;

	int ret = -1;

	if (!p->fd_ctl) {
		pr_err("No CTL for TTY dump, likely SCM case\n");
		return -1;
	}

	/*
	 * Make sure the structures the system provides us
	 * correlates well with protobuf templates.
	 */
	BUILD_BUG_ON(ARRAY_SIZE(t.c_cc) < TERMIOS_NCC);
	BUILD_BUG_ON(sizeof(termios.c_cc) != sizeof(void *));
	BUILD_BUG_ON((sizeof(termios.c_cc) * TERMIOS_NCC) < sizeof(t.c_cc));

	pti = parasite_dump_tty(p->fd_ctl, p->fd, driver->type);
	if (!pti)
		return -1;

	dinfo = xzalloc(sizeof(*dinfo));
	if (!dinfo)
		return -1;

	dinfo->id = id;
	dinfo->sid = pti->sid;
	dinfo->pgrp = pti->pgrp;
	dinfo->pid_real = p->pid;
	dinfo->fd = p->fd;
	dinfo->mnt_id = p->mnt_id;
	dinfo->driver = driver;
	dinfo->flags = p->flags;

	if (is_pty(driver)) {
		dinfo->lfd = dup(lfd);
		if (dinfo->lfd < 0) {
			pr_perror("Can't dup local fd on %#x", id);
			xfree(dinfo);
			return -1;
		}
		dinfo->index = index;
	} else {
		dinfo->index = -1;
		dinfo->lfd = -1;
	}

	list_add_tail(&dinfo->list, &all_ttys);

	info.id = id;
	info.sid = pti->sid;
	info.pgrp = pti->pgrp;
	info.rdev = p->stat.st_rdev;
	info.dev = p->stat.st_dev;
	info.has_dev = true;
	info.locked = pti->st_lock;
	info.exclusive = pti->st_excl;
	info.packet_mode = pti->st_pckt;

	info.has_uid = true;
	info.uid = userns_uid(p->stat.st_uid);
	info.has_gid = true;
	info.gid = userns_gid(p->stat.st_gid);

	info.type = driver->type;
	if (info.type == TTY_TYPE__PTY) {
		info.pty = &pty;
		pty.index = index;
	}

	/*
	 * Nothing we can do on hanging up terminal,
	 * just write out minimum information we can
	 * gather.
	 */
	if (pti->hangup)
		return pb_write_one(img_from_set(glob_imgset, CR_FD_TTY_INFO), &info, PB_TTY_INFO);

	/*
	 * Now trace the paired/unpaired ttys. For example
	 * the task might have slave peer assigned but no
	 * master peer. Such "detached" master peers are
	 * not yet supported by our tool and better to
	 * inform a user about such situation.
	 */
	if (is_pty(driver))
		tty_test_and_set(id, tty_active_pairs);

	info.termios = &termios;
	info.termios_locked = &termios_locked;
	info.winsize = &winsize;

	termios.n_c_cc = TERMIOS_NCC;
	termios.c_cc = xmalloc(pb_repeated_size(&termios, c_cc));

	termios_locked.n_c_cc = TERMIOS_NCC;
	termios_locked.c_cc = xmalloc(pb_repeated_size(&termios_locked, c_cc));

	if (!termios.c_cc || !termios_locked.c_cc)
		goto out;

	memzero(&t, sizeof(t));
	if (ioctl(lfd, TCGETS, &t) < 0) {
		pr_perror("Can't get tty params on %#x", id);
		goto out;
	}
	termios_copy(&termios, &t);

	memzero(&t, sizeof(t));
	if (ioctl(lfd, TIOCGLCKTRMIOS, &t) < 0) {
		pr_perror("Can't get tty locked params on %#x", id);
		goto out;
	}
	termios_copy(&termios_locked, &t);

	memzero(&w, sizeof(w));
	if (ioctl(lfd, TIOCGWINSZ, &w) < 0) {
		pr_perror("Can't get tty window params on %#x", id);
		goto out;
	}
	winsize_copy(&winsize, &w);

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_TTY_INFO), &info, PB_TTY_INFO);
out:
	xfree(termios.c_cc);
	xfree(termios_locked.c_cc);
	return ret;
}

static int dump_one_tty(int lfd, u32 id, const struct fd_parms *p)
{
	TtyFileEntry e = TTY_FILE_ENTRY__INIT;
	int ret = 0, index = -1;
	struct tty_driver *driver;

	pr_info("Dumping tty %d with id %#x\n", lfd, id);

	driver = get_tty_driver(p->stat.st_rdev, p->stat.st_dev);
	if (driver == NULL) {
		pr_err("Unable to find a tty driver (rdev %#" PRIx64 " dev %#" PRIx64 ")\n", p->stat.st_rdev,
		       p->stat.st_dev);
		return -1;
	}

	if (driver->fd_get_index)
		index = driver->fd_get_index(lfd, p);
	else
		index = driver->index;

	if (index == INDEX_ERR) {
		pr_info("Can't obtain index on tty %d id %#x\n", lfd, id);
		return -1;
	}

	e.id = id;
	e.tty_info_id = tty_gen_id(driver, index);
	e.flags = p->flags;
	e.fown = (FownEntry *)&p->fown;

	if (driver->type != TTY_TYPE__EXT_TTY) {
		u32 rf_id;

		fd_id_generate_special(NULL, &rf_id);
		if (dump_one_reg_file(lfd, rf_id, p))
			return -1;

		e.has_regf_id = true;
		e.regf_id = rf_id;
	}

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
		ret = dump_tty_info(lfd, e.tty_info_id, p, driver, index);

	if (!ret) {
		FileEntry fe = FILE_ENTRY__INIT;

		fe.type = FD_TYPES__TTY;
		fe.id = e.id;
		fe.tty = &e;
		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
	}

	return ret;
}

const struct fdtype_ops tty_dump_ops = {
	.type = FD_TYPES__TTY,
	.dump = dump_one_tty,
};

static int tty_reblock(int id, int lfd, int flags)
{
	static const int fmask = O_RDWR | O_NONBLOCK;
	int ret;

	if ((flags & fmask) != fmask) {
		if (fcntl(lfd, F_SETFL, flags)) {
			ret = -errno;
			pr_perror("Can't revert mode back to %o on (%#x)", fmask, id);
			return ret;
		}
	}

	return 0;
}

static int tty_unblock(int id, int lfd, int flags)
{
	static const int fmask = O_RDWR | O_NONBLOCK;
	int ret;

	if ((flags & fmask) != fmask) {
		if (fcntl(lfd, F_SETFL, fmask)) {
			ret = -errno;
			pr_perror("Can't change mode to %o on (%#x)", fmask, id);
			return ret;
		}
	}

	return 0;
}

static int tty_do_dump_queued_data(struct tty_dump_info *dinfo)
{
	TtyDataEntry e = TTY_DATA_ENTRY__INIT;
	size_t off = 0, size = 16384;
	char *buf;
	int ret;

	buf = xmalloc(size);
	if (!buf)
		return -ENOMEM;

	ret = tty_unblock(dinfo->id, dinfo->lfd, dinfo->flags);
	if (ret) {
		xfree(buf);
		return ret;
	}

	while (1) {
		ret = read(dinfo->lfd, &buf[off], size - off);
		if (ret == 0) {
			pr_debug("No more data on tty (%s %#x)\n", dinfo->driver->name, dinfo->id);
			break;
		} else if (ret < 0) {
			if (errno == EAGAIN) {
				pr_debug("Not waiting data tty (%s %#x)\n", dinfo->driver->name, dinfo->id);
				break;
			} else {
				ret = -errno;
				pr_perror("Can't read data from tty (%s %#x)", dinfo->driver->name, dinfo->id);
				xfree(buf);
				return ret;
			}
		}

		off += ret;
		pr_debug("Read %d bytes (%d) from tty (%s %#x)\n", ret, (int)off, dinfo->driver->name, dinfo->id);

		if (off >= size) {
			pr_err("The tty (%s %#x) queued data overflow %zu bytes limit\n", dinfo->driver->name,
			       dinfo->id, size);
			off = size;
			break;
		}
	}

	if (off) {
		dinfo->tty_data = buf;
		dinfo->tty_data_size = off;

		e.tty_id = dinfo->id;
		e.data.data = (void *)buf;
		e.data.len = off;

		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_TTY_DATA), &e, PB_TTY_DATA);
	} else {
		xfree(buf);
		ret = 0;
	}

	return ret;
}

/*
 * If error happens here, so be it, ttys are not delivering
 * data with guaranteed results.
 */
static void __tty_do_writeback_queued_data(struct tty_dump_info *dinfo)
{
	if (dinfo->tty_data) {
		if (write(dinfo->link->lfd, dinfo->tty_data, dinfo->tty_data_size) != dinfo->tty_data_size)
			pr_perror("Can't writeback to tty (%#x)", dinfo->id);
	}
	tty_reblock(dinfo->link->id, dinfo->link->lfd, dinfo->link->flags);
}

static void tty_do_writeback_queued_data(struct tty_dump_info *dinfo)
{
	__tty_do_writeback_queued_data(dinfo);
	__tty_do_writeback_queued_data(dinfo->link);
}

static void tty_dinfo_free(struct tty_dump_info *dinfo)
{
	list_del(&dinfo->list);
	close_safe(&dinfo->lfd);
	xfree(dinfo->tty_data);
	xfree(dinfo);
}

/*
 * Dumping queued data must be done at the very end of the
 * checkpoint procedure -- it's tail optimization, we trying
 * to defer this procedure until everything else passed
 * successfully because in real it is time consuming on
 * its own which might require writing data back to the
 * former peers if case something go wrong.
 *
 * Moreover when we gather PTYs peers into own list we
 * do it in destructive way -- the former @all_ttys
 * list get modified (one of the peer get moved from
 * @all_ttys to @all_ptys list) because otherwise we
 * will have to add one more entry into tty_dump_info,
 * thus we simply reuse the @list entry for own needs.
 */
static int tty_dump_queued_data(void)
{
	struct tty_dump_info *dinfo, *peer, *n;
	LIST_HEAD(all_ptys);
	int ret = 0;

	/*
	 * Link PTY peers, and move one of linked
	 * into separate list.
	 */
	list_for_each_entry_safe(dinfo, n, &all_ttys, list) {
		if (!is_pty(dinfo->driver) || dinfo->link)
			continue;

		peer = dinfo;
		list_for_each_entry_continue(peer, &all_ttys, list) {
			if (!is_pty(peer->driver) || peer->link)
				continue;

			if (peer->index == dinfo->index) {
				dinfo->link = peer;
				peer->link = dinfo;
				pr_debug("Link PTYs (%#x)\n", dinfo->id);

				list_move(&dinfo->list, &all_ptys);
			}
		}
	}

	/*
	 * Once linked fetch the queued data if present.
	 */
	list_for_each_entry(dinfo, &all_ptys, list) {
		ret = tty_do_dump_queued_data(dinfo);
		if (ret)
			break;
		ret = tty_do_dump_queued_data(dinfo->link);
		if (ret)
			break;
	}

	if (ret || opts.final_state != TASK_DEAD) {
		list_for_each_entry(dinfo, &all_ptys, list)
			tty_do_writeback_queued_data(dinfo);
	}

	list_for_each_entry_safe(dinfo, n, &all_ptys, list) {
		tty_dinfo_free(dinfo->link);
		tty_dinfo_free(dinfo);
	}

	list_for_each_entry_safe(dinfo, n, &all_ttys, list)
		tty_dinfo_free(dinfo);

	return ret;
}

static int tty_verify_ctty(void)
{
	struct tty_dump_info *d, *p;

	list_for_each_entry(d, &all_ttys, list) {
		struct tty_dump_info *n = NULL;

		if (d->driver->type != TTY_TYPE__CTTY)
			continue;

		list_for_each_entry(p, &all_ttys, list) {
			if (!is_pty(p->driver) || p->sid != d->sid || p->pgrp != d->sid)
				continue;
			n = p;
			break;
		}

		if (!n) {
			pr_err("ctty inheritance detected sid/pgrp %d, "
			       "no PTY peer with sid/pgrp needed\n",
			       d->sid);
			return -ENOENT;
		} else if (n->pid_real != d->pid_real) {
			pr_err("ctty inheritance detected sid/pgrp %d "
			       "(ctty pid_real %d pty pid_real %d)\n",
			       d->sid, d->pid_real, n->pid_real);
			return -ENOENT;
		}
	}

	return 0;
}

int tty_post_actions(void)
{
	if (tty_verify_ctty())
		return -1;
	if (tty_verify_active_pairs())
		return -1;
	else if (tty_dump_queued_data())
		return -1;
	return 0;
}

int tty_prep_fds(void)
{
	if (!opts.shell_job)
		return 0;

	if (!isatty(STDIN_FILENO))
		pr_info("Standard stream is not a terminal, may fail later\n");
	else
		stdin_isatty = true;

	self_stdin_fdid = fdstore_add(STDIN_FILENO);
	if (self_stdin_fdid < 0) {
		pr_err("Can't place stdin fd to fdstore\n");
		return -1;
	}

	return 0;
}

static int open_pty(void *arg, int flags)
{
	int dfd = (unsigned long)arg;
	/*
	 * Never set as a control terminal automatically, all
	 * ctty magic happens only in tty_set_sid().
	 */
	flags |= O_NOCTTY;
	return openat(dfd, "ptmx", flags);
}

/* Create a pty pair and save a master descriptor in fdstore */
static int pty_create_ptmx_index(int dfd, int index, int flags)
{
	struct tty_info *info;
	int fd, id;

	fd = __pty_open_ptmx_index(index, flags, open_pty, (void *)(unsigned long)dfd, "ptmx");
	if (fd < 0)
		return -1;

	id = fdstore_add(fd);
	if (id < 0)
		return -1;
	close(fd);

	list_for_each_entry(info, &all_ttys, list) {
		if (!is_pty(info->driver))
			continue;

		if (info->tie->pty->index == index) {
			info->fdstore_id = id;
		}
	}

	return 0;
}

/*
 * Here we check that a master of a bind-mounted slave was opened in the root
 * mount namespace. The problem is that we restore all mounts in the root mount
 * namespace. Only when all mounts are restored, we create other mount
 * namespaces. So when we are restoring mounts, we can open files only in the
 * root mount namespace.
 */
int devpts_check_bindmount(struct mount_info *m)
{
	struct tty_dump_info *dinfo = NULL;
	struct mount_info *master_mp;
	int index;

	if (strcmp(m->root, "/") == 0 || strcmp(m->root, "/ptmx") == 0)
		return 0;

	if (sscanf(m->root, "/%d", &index) != 1) {
		pr_err("Unable to parse %s\n", m->root);
		return -1;
	}

	list_for_each_entry(dinfo, &all_ttys, list) {
		if (!is_pty(dinfo->driver))
			continue;

		if (dinfo->driver->subtype != TTY_SUBTYPE_MASTER)
			continue;

		if (dinfo->index == index)
			goto found;
	}

	if (opts.orphan_pts_master) /* external master */
		return 0;

	pr_err("Unable to find a master for %s\n", m->root);
	return -1;

found:
	/* mnt_id isn't reported in fdinfo, so here is only one mntns */
	if (dinfo->mnt_id == -1)
		return 0;

	master_mp = lookup_mnt_id(dinfo->mnt_id);
	if (!master_mp) {
		pr_err("Unable to find a mount %d\n", dinfo->mnt_id);
		return -1;
	}

	if (master_mp->nsid->type != NS_ROOT) {
		pr_err("The master for %s isn't from the root mntns\n", m->root);
		return -1;
	}

	return 0;
}

/* Restore slave pty-s which have to be bind-mounted to somewhere */
int devpts_restore(struct mount_info *pm)
{
	struct mount_info *bm;
	int dfd, exit_code = -1;

	dfd = open(service_mountpoint(pm), O_RDONLY);
	if (dfd < 0) {
		pr_perror("Unable to open %s", service_mountpoint(pm));
		return -1;
	}

	list_for_each_entry(bm, &pm->mnt_bind, mnt_bind) {
		int idx;
		struct stat st;

		if (sscanf(bm->root, "/%d", &idx) < 1)
			continue;

		if (fstatat(dfd, bm->root + 1, &st, 0) == 0)
			continue;

		pr_debug("Create a slave tty %d\n", idx);
		if (pty_create_ptmx_index(dfd, idx, O_RDWR))
			goto err;
	}

	exit_code = 0;
err:
	close(dfd);
	return exit_code;
}
