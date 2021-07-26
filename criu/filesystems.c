#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "common/config.h"
#include "int.h"
#include "common/compiler.h"
#include "xmalloc.h"
#include "cr_options.h"
#include "filesystems.h"
#include "namespaces.h"
#include "mount.h"
#include "pstree.h"
#include "kerndat.h"
#include "protobuf.h"
#include "autofs.h"
#include "util.h"
#include "fs-magic.h"
#include "tty.h"

#include "images/mnt.pb-c.h"
#include "images/binfmt-misc.pb-c.h"

static int attach_option(struct mount_info *pm, char *opt)
{
	if (pm->options[0] == '\0')
		pm->options = xstrcat(pm->options, "%s", opt);
	else
		pm->options = xstrcat(pm->options, ",%s", opt);
	return pm->options ? 0 : -1;
}

#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
struct binfmt_misc_info {
	BinfmtMiscEntry *bme;
	struct list_head list;
};

LIST_HEAD(binfmt_misc_list);

static int binfmt_misc_parse_or_collect(struct mount_info *pm)
{
	opts.has_binfmt_misc = true;
	return 0;
}

static int binfmt_misc_virtual(struct mount_info *pm)
{
	return kerndat_fs_virtualized(KERNDAT_FS_STAT_BINFMT_MISC, pm->s_dev);
}

static int parse_binfmt_misc_entry(struct bfd *f, BinfmtMiscEntry *bme)
{
	while (1) {
		char *str;

		str = breadline(f);
		if (IS_ERR(str))
			return -1;
		if (!str)
			break;

		if (!strncmp(str, "enabled", 7)) {
			bme->enabled = true;
			continue;
		}

		if (!strncmp(str, "disabled", 8))
			continue;

		if (!strncmp(str, "offset ", 7)) {
			if (sscanf(str + 7, "%i", &bme->offset) != 1)
				return -1;
			bme->has_offset = true;
			continue;
		}

#define DUP_EQUAL_AS(key, member)                         \
	if (!strncmp(str, key, strlen(key))) {            \
		bme->member = xstrdup(str + strlen(key)); \
		if (!bme->member)                         \
			return -1;                        \
		continue;                                 \
	}
		DUP_EQUAL_AS("interpreter ", interpreter)
		DUP_EQUAL_AS("flags: ", flags)
		DUP_EQUAL_AS("extension .", extension)
		DUP_EQUAL_AS("magic ", magic)
		DUP_EQUAL_AS("mask ", mask)
#undef DUP_EQUAL_AS

		pr_perror("binfmt_misc: unsupported feature %s", str);
		return -1;
	}

	return 0;
}

static int dump_binfmt_misc_entry(int dfd, char *name, struct cr_img *img)
{
	BinfmtMiscEntry bme = BINFMT_MISC_ENTRY__INIT;
	struct bfd f;
	int ret = -1;

	f.fd = openat(dfd, name, O_RDONLY);
	if (f.fd < 0) {
		pr_perror("binfmt_misc: can't open %s", name);
		return -1;
	}

	if (bfdopenr(&f))
		return -1;

	if (parse_binfmt_misc_entry(&f, &bme))
		goto err;

	bme.name = name;

	if (pb_write_one(img, &bme, PB_BINFMT_MISC))
		goto err;
	ret = 0;
err:
	free(bme.interpreter);
	free(bme.flags);
	free(bme.extension);
	free(bme.magic);
	free(bme.mask);
	bclose(&f);
	return ret;
}

static int binfmt_misc_dump(struct mount_info *pm)
{
	static bool dumped = false;
	struct cr_img *img = NULL;
	struct dirent *de;
	DIR *fdir = NULL;
	int fd, ret;

	ret = binfmt_misc_virtual(pm);
	if (ret <= 0)
		return ret;

	if (dumped) {
		pr_err("Second binfmt_misc superblock\n");
		return -1;
	}
	dumped = true;

	fd = open_mountpoint(pm);
	if (fd < 0)
		return fd;

	fdir = fdopendir(fd);
	if (fdir == NULL) {
		close(fd);
		return -1;
	}

	ret = -1;
	while ((de = readdir(fdir))) {
		if (dir_dots(de))
			continue;
		if (!strcmp(de->d_name, "register"))
			continue;
		if (!strcmp(de->d_name, "status"))
			continue;

		if (!img) {
			/* Create image only if an entry exists, i.e. here */
			img = open_image(CR_FD_BINFMT_MISC, O_DUMP);
			if (!img)
				goto out;
		}

		if (dump_binfmt_misc_entry(fd, de->d_name, img))
			goto out;
	}

	ret = 0;
out:
	if (img)
		close_image(img);
	closedir(fdir);
	return ret;
}

static int write_binfmt_misc_entry(char *mp, char *buf, BinfmtMiscEntry *bme)
{
	int fd, len, ret = -1;
	char path[PATH_MAX + 1];

	snprintf(path, PATH_MAX, "%s/register", mp);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("binfmt_misc: can't open %s", path);
		return -1;
	}

	len = strlen(buf);

	if (write(fd, buf, len) != len) {
		pr_perror("binfmt_misc: can't write to %s", path);
		goto close;
	}

	if (!bme->enabled) {
		close(fd);
		snprintf(path, PATH_MAX, "%s/%s", mp, bme->name);

		fd = open(path, O_WRONLY);
		if (fd < 0) {
			pr_perror("binfmt_misc: can't open %s", path);
			goto out;
		}
		if (write(fd, "0", 1) != 1) {
			pr_perror("binfmt_misc: can't write to %s", path);
			goto close;
		}
	}

	ret = 0;
close:
	close(fd);
out:
	return ret;
}

#define BINFMT_MISC_STR (1920 + 1)
static int make_bfmtm_magic_str(char *buf, BinfmtMiscEntry *bme)
{
	int i, len;

	/*
	 * Format is ":name:type(M):offset:magic:mask:interpreter:flags".
	 * Magic and mask are special fields. Kernel outputs them as
	 * a sequence of hexadecimal numbers (abc -> 616263), and we
	 * dump them without changes. But for registering a new entry
	 * it expects every byte is prepended with \x, i.e. \x61\x62\x63.
	 */
	len = strlen(bme->name) + 3 /* offset < 128 */ + 2 * strlen(bme->magic) +
	      (bme->mask ? 2 * strlen(bme->mask) : 0) + strlen(bme->interpreter) +
	      (bme->flags ? strlen(bme->flags) : 0) + strlen(":::::::");

	if ((len > BINFMT_MISC_STR - 1) || bme->offset > 128)
		return -1;

	buf += sprintf(buf, ":%s:M:%d:", bme->name, bme->offset);

	len = strlen(bme->magic);
	for (i = 0; i < len; i += 2)
		buf += sprintf(buf, "\\x%c%c", bme->magic[i], bme->magic[i + 1]);

	buf += sprintf(buf, ":");

	if (bme->mask) {
		len = strlen(bme->mask);
		for (i = 0; i < len; i += 2)
			buf += sprintf(buf, "\\x%c%c", bme->mask[i], bme->mask[i + 1]);
	}

	sprintf(buf, ":%s:%s", bme->interpreter, bme->flags ?: "\0");

	return 1;
}

static int binfmt_misc_restore_bme(struct mount_info *mi, BinfmtMiscEntry *bme, char *buf)
{
	int ret;

	if (!bme->name || !bme->interpreter)
		goto bad_dump;

	/* Either magic or extension should be there */
	if (bme->magic) {
		ret = make_bfmtm_magic_str(buf, bme);
	} else if (bme->extension) {
		/* :name:E::extension::interpreter:flags */
		ret = snprintf(buf, BINFMT_MISC_STR, ":%s:E::%s::%s:%s", bme->name, bme->extension, bme->interpreter,
			       bme->flags ?: "\0");
		if (ret >= BINFMT_MISC_STR) /* output truncated */
			ret = -1;
	} else
		ret = -1;

	if (ret < 0)
		goto bad_dump;

	pr_debug("binfmt_misc_pattern=%s\n", buf);
	ret = write_binfmt_misc_entry(mi->mountpoint, buf, bme);

	return ret;

bad_dump:
	pr_perror("binfmt_misc: bad dump");
	return -1;
}

static int binfmt_misc_restore(struct mount_info *mi)
{
	struct cr_img *img;
	char *buf;
	int ret = -1;

	buf = xmalloc(BINFMT_MISC_STR);
	if (!buf)
		return -1;

	if (!list_empty(&binfmt_misc_list)) {
		struct binfmt_misc_info *bmi;

		list_for_each_entry(bmi, &binfmt_misc_list, list) {
			ret = binfmt_misc_restore_bme(mi, bmi->bme, buf);
			if (ret)
				break;
		}
		goto free_buf;
	}

	img = open_image(CR_FD_BINFMT_MISC_OLD, O_RSTR, mi->s_dev);
	if (!img) {
		pr_err("Can't open binfmt_misc_old image\n");
		goto free_buf;
	} else if (empty_image(img)) {
		close_image(img);
		ret = 0;
		goto free_buf;
	}

	ret = 0;
	while (ret == 0) {
		BinfmtMiscEntry *bme;

		ret = pb_read_one_eof(img, &bme, PB_BINFMT_MISC);
		if (ret <= 0)
			break;

		ret = binfmt_misc_restore_bme(mi, bme, buf);

		binfmt_misc_entry__free_unpacked(bme, NULL);
	}

	close_image(img);
free_buf:
	free(buf);
	return ret;
}

static int collect_one_binfmt_misc_entry(void *o, ProtobufCMessage *msg, struct cr_img *img)
{
	struct binfmt_misc_info *bmi = o;

	bmi->bme = pb_msg(msg, BinfmtMiscEntry);
	list_add_tail(&bmi->list, &binfmt_misc_list);

	return 0;
}

struct collect_image_info binfmt_misc_cinfo = {
	.fd_type = CR_FD_BINFMT_MISC,
	.pb_type = PB_BINFMT_MISC,
	.priv_size = sizeof(struct binfmt_misc_info),
	.collect = collect_one_binfmt_misc_entry,
};

int collect_binfmt_misc(void)
{
	return collect_image(&binfmt_misc_cinfo);
}
#else
#define binfmt_misc_dump	     NULL
#define binfmt_misc_restore	     NULL
#define binfmt_misc_parse_or_collect NULL
#endif

static int tmpfs_dump(struct mount_info *pm)
{
	int ret = -1, fd = -1, userns_pid = -1;
	struct cr_img *img;
	int tmp_fds[3], ntmp_fds = 0, i;

	fd = open_mountpoint(pm);
	if (fd < 0)
		return MNT_UNREACHABLE;

	/*
	 * fd should not be one of standard descriptors, because
	 * cr_system_userns will override them.
	 */
	for (i = 0; i < 3; i++) {
		if (fd > 2)
			break;
		tmp_fds[ntmp_fds++] = fd;
		fd = dup(fd);
		if (fd < 0) {
			pr_perror("Unable to duplicate a file descriptor");
			goto out;
		}
	}

	if (move_fd_from(&fd, STDIN_FILENO) < 0)
		goto out;

	if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC) == -1) {
		pr_perror("Can not drop FD_CLOEXEC");
		goto out;
	}

	img = open_image(CR_FD_TMPFS_DEV, O_DUMP, pm->s_dev);
	if (!img)
		goto out;

	if (root_ns_mask & CLONE_NEWUSER)
		userns_pid = root_item->pid->real;

	ret = cr_system_userns(fd, img_raw_fd(img), -1, "tar",
			       (char *[]){ "tar", "--create", "--gzip", "--no-unquote", "--no-wildcards",
					   "--one-file-system", "--check-links", "--preserve-permissions", "--sparse",
					   "--numeric-owner", "--directory", "/proc/self/fd/0", ".", NULL },
			       0, userns_pid);

	if (ret)
		pr_err("Can't dump tmpfs content\n");

	close_image(img);
out:
	for (i = 0; i < ntmp_fds; i++)
		close(tmp_fds[i]);
	close_safe(&fd);
	return ret;
}

static int tmpfs_restore(struct mount_info *pm)
{
	int ret;
	struct cr_img *img;

	img = open_image(CR_FD_TMPFS_DEV, O_RSTR, pm->s_dev);
	if (empty_image(img)) {
		close_image(img);
		img = open_image(CR_FD_TMPFS_IMG, O_RSTR, pm->mnt_id);
	}
	if (!img)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return -1;
	}

	ret = cr_system(img_raw_fd(img), -1, -1, "tar",
			(char *[]){ "tar", "--extract", "--gzip", "--no-unquote", "--no-wildcards", "--directory",
				    pm->mountpoint, NULL },
			0);
	close_image(img);

	if (ret) {
		pr_err("Can't restore tmpfs content\n");
		return -1;
	}

	return 0;
}

/*
 * Virtualized devtmpfs on any side (dump or restore)
 * means, that we should try to handle it as a plain
 * tmpfs.
 *
 * Interesting case -- shared on dump and virtual on
 * restore -- will fail, since no tarball with the fs
 * contents will be found.
 */

static int devtmpfs_virtual(struct mount_info *pm)
{
	return kerndat_fs_virtualized(KERNDAT_FS_STAT_DEVTMPFS, pm->s_dev);
}

static int devtmpfs_dump(struct mount_info *pm)
{
	int ret;

	ret = devtmpfs_virtual(pm);
	if (ret == 1)
		ret = tmpfs_dump(pm);

	return ret;
}

static int devtmpfs_restore(struct mount_info *pm)
{
	int ret;

	ret = devtmpfs_virtual(pm);
	if (ret == 1)
		ret = tmpfs_restore(pm);

	return ret;
}

/* Is it mounted w or w/o the newinstance option */
static int devpts_parse(struct mount_info *pm)
{
	int ret;

	ret = kerndat_fs_virtualized(KERNDAT_FS_STAT_DEVPTS, pm->s_dev);
	if (ret <= 0)
		return ret;

	/*
	 * Kernel hides this option, but if the fs instance
	 * is new (virtualized) we know that it was created
	 * with -o newinstance.
	 */
	return attach_option(pm, "newinstance");
}

static int fusectl_dump(struct mount_info *pm)
{
	int fd, ret = -1;
	struct dirent *de;
	DIR *fdir = NULL;

	fd = open_mountpoint(pm);
	if (fd < 0)
		return fd;

	fdir = fdopendir(fd);
	if (fdir == NULL) {
		close(fd);
		return -1;
	}

	while ((de = readdir(fdir))) {
		int id;
		struct mount_info *it;

		if (dir_dots(de))
			continue;

		if (sscanf(de->d_name, "%d", &id) != 1) {
			pr_err("wrong number of items scanned in fusectl dump\n");
			goto out;
		}

		for (it = mntinfo; it; it = it->next) {
			if (it->fstype->code == FSTYPE__FUSE && id == kdev_minor(it->s_dev) && !it->external) {
				pr_err("%s is a fuse mount but not external\n", it->mountpoint);
				goto out;
			}
		}
	}

	ret = 0;
out:
	closedir(fdir);
	return ret;
}

static int debugfs_parse(struct mount_info *pm)
{
	/* tracefs is automounted underneath debugfs sometimes, and the
	 * kernel's overmounting protection prevents us from mounting debugfs
	 * first without tracefs, so let's always mount debugfs MS_REC.
	 */
	pm->flags |= MS_REC;

	return 0;
}

static int tracefs_parse(struct mount_info *pm)
{
	return 1;
}

static bool cgroup_sb_equal(struct mount_info *a, struct mount_info *b)
{
	if (a->private && b->private && strcmp(a->private, b->private))
		return false;
	if (strcmp(a->options, b->options))
		return false;

	return true;
}

static int cgroup_parse(struct mount_info *pm)
{
	if (!(root_ns_mask & CLONE_NEWCGROUP))
		return 0;

	/* cgroup namespaced mounts don't look rooted to CRIU, so let's fake it
	 * here.
	 */
	pm->private = pm->root;
	pm->root = xstrdup("/");
	if (!pm->root)
		return -1;

	return 0;
}

static bool btrfs_sb_equal(struct mount_info *a, struct mount_info *b)
{
	/* There is a btrfs bug where it doesn't emit subvol= correctly when
	 * files are bind mounted, so let's ignore it for now.
	 * https://marc.info/?l=linux-btrfs&m=145857372803614&w=2
	 */

	char *posa = strstr(a->options, "subvol="), *posb = strstr(b->options, "subvol=");
	bool equal;

	if (!posa || !posb) {
		pr_err("invalid btrfs options, no subvol argument\n");
		return false;
	}

	*posa = *posb = 0;
	equal = !strcmp(a->options, b->options);
	*posa = *posb = 's';

	if (!equal)
		return false;

	posa = strchr(posa, ',');
	posb = strchr(posb, ',');

	if ((posa && !posb) || (!posa && posb))
		return false;

	if (posa && strcmp(posa, posb))
		return false;

	return true;
}

static int dump_empty_fs(struct mount_info *pm)
{
	int fd, ret = -1;

	fd = open_mountpoint(pm);
	if (fd < 0)
		return fd;

	ret = is_empty_dir(fd);
	if (ret == 0) {
		pr_err("%s isn't empty\n", pm->fstype->name);
		return -1;
	}

	return ret == 1 ? 0 : -1;
}

/*
 * Some fses (fuse) cannot be dumped, so we should always fail on dump/restore
 * of these fses.
 */
static int always_fail(struct mount_info *pm)
{
	pr_err("failed to dump fs %s (%s): always fail\n", pm->mountpoint, pm->fstype->name);
	return -1;
}

static struct fstype fstypes[] = {
	{
		.name = "unsupported",
		.code = FSTYPE__UNSUPPORTED,
	},
	{
		.name = "auto_cr",
		.code = FSTYPE__AUTO,
	},
	{
		.name = "proc",
		.code = FSTYPE__PROC,
	},
	{
		.name = "sysfs",
		.code = FSTYPE__SYSFS,
	},
	{
		.name = "devtmpfs",
		.code = FSTYPE__DEVTMPFS,
		.dump = devtmpfs_dump,
		.restore = devtmpfs_restore,
	},
	{
		.name = "binfmt_misc",
		.parse = binfmt_misc_parse_or_collect,
		.collect = binfmt_misc_parse_or_collect,
		.code = FSTYPE__BINFMT_MISC,
		.dump = binfmt_misc_dump,
		.restore = binfmt_misc_restore,
	},
	{
		.name = "tmpfs",
		.code = FSTYPE__TMPFS,
		.dump = tmpfs_dump,
		.restore = tmpfs_restore,
	},
	{
		.name = "devpts",
		.parse = devpts_parse,
		.code = FSTYPE__DEVPTS,
		.restore = devpts_restore,
		.check_bindmount = devpts_check_bindmount,
	},
	{
		.name = "simfs",
		.code = FSTYPE__SIMFS,
	},
	{
		.name = "btrfs",
		.code = FSTYPE__UNSUPPORTED,
		.sb_equal = btrfs_sb_equal,
	},
	{
		.name = "pstore",
		.dump = dump_empty_fs,
		.code = FSTYPE__PSTORE,
	},
	{
		.name = "mqueue",
		.dump = dump_empty_fs,
		.code = FSTYPE__MQUEUE,
	},
	{
		.name = "securityfs",
		.code = FSTYPE__SECURITYFS,
	},
	{
		.name = "fusectl",
		.dump = fusectl_dump,
		.code = FSTYPE__FUSECTL,
	},
	{
		.name = "debugfs",
		.code = FSTYPE__DEBUGFS,
		.parse = debugfs_parse,
	},
	{
		.name = "tracefs",
		.code = FSTYPE__TRACEFS,
		.parse = tracefs_parse,
	},
	{
		.name = "cgroup",
		.code = FSTYPE__CGROUP,
		.parse = cgroup_parse,
		.sb_equal = cgroup_sb_equal,
	},
	{
		.name = "cgroup2",
		.code = FSTYPE__CGROUP2,
		.parse = cgroup_parse,
		.sb_equal = cgroup_sb_equal,
	},
	{
		.name = "aufs",
		.code = FSTYPE__AUFS,
		.parse = aufs_parse,
	},
	{
		.name = "fuse",
		.code = FSTYPE__FUSE,
		.dump = always_fail,
		.restore = always_fail,
	},
	{
		.name = "overlay",
		.code = FSTYPE__OVERLAYFS,
		.parse = overlayfs_parse,
	},
	{
		.name = "autofs",
		.code = FSTYPE__AUTOFS,
		.parse = autofs_parse,
		.dump = autofs_dump,
		.mount = autofs_mount,
	},
};

struct fstype *fstype_auto(void)
{
	return &fstypes[1];
}

static char fsauto_all[] = "all";
static char *fsauto_names;

static bool css_contains(const char *css, const char *str)
{
	int len = strlen(str);
	const char *cur;

	if (!len)
		return false;

	for (cur = css; (cur = strstr(cur, str)); cur += len) {
		if (cur > css && cur[-1] != ',')
			continue;
		if (cur[len] && cur[len] != ',')
			continue;
		return true;
	}

	return false;
}

static bool fsname_is_auto(const char *name)
{
	if (!fsauto_names)
		return false;

	if (fsauto_names == fsauto_all)
		return true;

	return css_contains(fsauto_names, name);
}

bool add_fsname_auto(const char *names)
{
	char *old = fsauto_names;

	if (old == fsauto_all)
		return true;

	if (css_contains(names, fsauto_all))
		fsauto_names = fsauto_all;
	else if (!old) {
		fsauto_names = xstrdup(names);
		if (!fsauto_names)
			abort();
	} else {
		if (asprintf(&fsauto_names, "%s,%s", old, names) < 0)
			fsauto_names = NULL;
	}

	xfree(old);
	return fsauto_names != NULL;
}

struct fstype *find_fstype_by_name(char *fst)
{
	int i;

	/*
	 * This fn is required for two things.
	 * 1st -- to check supported filesystems (as just mounting
	 * anything is wrong, almost every fs has its own features)
	 * 2nd -- save some space in the image (since we scan all
	 * names anyway)
	 */
	for (i = 1; i < ARRAY_SIZE(fstypes); i++) {
		struct fstype *fstype = fstypes + i;

		if (!strcmp(fstype->name, fst))
			return fstype;
	}

	if (fsname_is_auto(fst))
		return &fstypes[1];

	return &fstypes[0];
}

struct fstype *decode_fstype(u32 fst)
{
	int i;

	if (fst == FSTYPE__UNSUPPORTED)
		goto uns;

	for (i = 1; i < ARRAY_SIZE(fstypes); i++) {
		struct fstype *fstype = fstypes + i;

		if (!fstype->name)
			break;

		if (fstype->code == fst)
			return fstype;
	}
uns:
	return &fstypes[0];
}
