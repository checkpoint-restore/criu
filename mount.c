#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>

#include "crtools.h"
#include "types.h"
#include "util.h"
#include "log.h"
#include "mount.h"
#include "proc_parse.h"
#include "image.h"

#include "protobuf.h"
#include "protobuf/mnt.pb-c.h"

static struct mount_info *mntinfo;

int open_mount(unsigned int s_dev)
{
	struct mount_info *i;

	for (i = mntinfo; i != NULL; i = i->next)
		if (s_dev == i->s_dev)
			return open(i->mountpoint, O_RDONLY);

	return -ENOENT;
}

int collect_mount_info(void)
{
	pr_info("Collecting mountinfo\n");

	mntinfo = parse_mountinfo(getpid());
	if (!mntinfo) {
		pr_err("Parsing mountinfo %d failed\n", getpid());
		return -1;
	}

	return 0;
}

static struct mount_info *mnt_find_by_id(struct mount_info *list, int id)
{
	struct mount_info *m;

	for (m = list; m != NULL; m = m->next)
		if (m->mnt_id == id)
			return m;

	return NULL;
}

static struct mount_info *mnt_build_ids_tree(struct mount_info *list)
{
	struct mount_info *m, *root = NULL;

	/*
	 * Just resolve the mnt_id:parent_mnt_id relations
	 */

	pr_debug("\tBuilding plain mount tree\n");
	for (m = list; m != NULL; m = m->next) {
		struct mount_info *p;

		pr_debug("\t\tWorking on %d->%d\n", m->mnt_id, m->parent_mnt_id);
		p = mnt_find_by_id(list, m->parent_mnt_id);
		if (!p) {
			/* This should be / */
			if (root == NULL && !strcmp(m->mountpoint, "/")) {
				root = m;
				continue;
			}

			pr_err("Mountpoint %d w/o parent %d found @%s (root %s)\n",
					m->mnt_id, m->parent_mnt_id, m->mountpoint,
					root ? "found" : "not found");
			return NULL;
		}

		m->parent = p;
		list_add_tail(&m->siblings, &p->children);
	}

	if (!root) {
		pr_err("No root found for tree\n");
		return NULL;
	}

	return root;
}

static int mnt_depth(struct mount_info *m)
{
	int depth = 0;
	char *c;

	for (c = m->mountpoint; *c != '\0'; c++)
		if (*c == '/')
			depth++;

	return depth;
}

static void mnt_resort_siblings(struct mount_info *tree)
{
	struct mount_info *m, *p;
	LIST_HEAD(list);

	/*
	 * Put siblings of each node in an order they can be (u)mounted
	 * I.e. if we have mounts on foo/bar/, foo/bar/foobar/ and foo/
	 * we should put them in the foo/bar/foobar/, foo/bar/, foo/ order.
	 * Otherwise we will not be able to (u)mount them in a sequence.
	 *
	 * Funny, but all we need for this is to sort them in the descending
	 * order of the amount of /-s in a path =)
	 *
	 * Use stupid insertion sort here, we're not expecting mount trees
	 * to contain hundreds (or more) elements.
	 */

	pr_info("\tResorting siblings on %d\n", tree->mnt_id);
	while (!list_empty(&tree->children)) {
		int depth;

		m = list_first_entry(&tree->children, struct mount_info, siblings);
		list_del(&m->siblings);

		depth = mnt_depth(m);
		list_for_each_entry(p, &list, siblings)
			if (mnt_depth(p) <= depth)
				break;

		list_add(&m->siblings, &p->siblings);
		mnt_resort_siblings(m);
	}

	list_splice(&list, &tree->children);
}

static void mnt_tree_show(struct mount_info *tree, int off)
{
	struct mount_info *m;

	pr_info("%*s[%s](%d->%d)\n", off, "",
			tree->mountpoint, tree->mnt_id, tree->parent_mnt_id);

	list_for_each_entry(m, &tree->children, siblings)
		mnt_tree_show(m, off + 1);

	pr_info("%*s<--\n", off, "");
}

static struct mount_info *mnt_build_tree(struct mount_info *list)
{
	struct mount_info *tree;

	/*
	 * Organize them in a sequence in which they can be mounted/umounted.
	 */

	pr_info("Building mountpoints tree\n");
	tree = mnt_build_ids_tree(list);
	if (!tree)
		return NULL;

	mnt_resort_siblings(tree);
	pr_info("Done:\n");
	mnt_tree_show(tree, 0);
	return tree;
}

static char *fstypes[] = {
	"unsupported",
	"proc",
	"sysfs",
};

static u32 encode_fstype(char *fst)
{
	int i;

	/*
	 * This fn is required for two things.
	 * 1st -- to check supported filesystems (as just mounting
	 * anything is wrong, almost every fs has its own features)
	 * 2nd -- save some space in the image (since we scan all
	 * names anyway)
	 */

	for (i = 0; i < ARRAY_SIZE(fstypes); i++)
		if (!strcmp(fstypes[i], fst))
			return i;

	return 0;
}

static char *decode_fstype(u32 fst)
{
	static char uns[12];

	if (fst >= ARRAY_SIZE(fstypes)) {
		sprintf(uns, "x%d", fst);
		return uns;
	}

	return fstypes[fst];
}

static inline int is_root(char *p)
{
	return p[0] == '/' && p[1] == '\0';
}

static inline int is_root_mount(struct mount_info *mi)
{
	return is_root(mi->mountpoint);
}

static int dump_one_mountpoint(struct mount_info *pm, int fd)
{
	MntEntry me = MNT_ENTRY__INIT;

	pr_info("\t%d: %x:%s @ %s\n", pm->mnt_id, pm->s_dev,
			pm->root, pm->mountpoint);

	me.fstype		= encode_fstype(pm->fstype);
	me.mnt_id		= pm->mnt_id;
	me.root_dev		= pm->s_dev;
	me.parent_mnt_id	= pm->parent_mnt_id;
	me.flags		= pm->flags;
	me.root			= pm->root;
	me.mountpoint		= pm->mountpoint;
	me.source		= pm->source;
	me.options		= pm->options;

	if (!me.fstype && !is_root_mount(pm)) {
		pr_err("FS %s unsupported\n", pm->fstype);
		return -1;
	}

	if (pb_write(fd, &me, mnt_entry))
		return -1;

	return 0;
}

int dump_mnt_ns(int ns_pid, struct cr_fdset *fdset)
{
	struct mount_info *pm;
	int img_fd;

	pm = parse_mountinfo(ns_pid);
	if (!pm) {
		pr_err("Can't parse %d's mountinfo\n", ns_pid);
		return -1;
	}

	pr_info("Dumping mountpoints\n");

	img_fd = fdset_fd(fdset, CR_FD_MOUNTPOINTS);
	do {
		struct mount_info *n = pm->next;

		if (dump_one_mountpoint(pm, img_fd))
			return -1;

		xfree(pm);
		pm = n;
	} while (pm);

	return 0;
}

#define MNT_TREE_WALK(_mi, _el, _fn_f, _fn_r) do {				\
		while (1) {							\
			if (_fn_f(_mi))						\
				return -1;					\
			if (!list_empty(&_mi->children)) {			\
				_mi = list_entry(_mi->children._el,		\
						struct mount_info, siblings);	\
				continue;					\
			}							\
	up:									\
			if (_fn_r(_mi))						\
				return -1;					\
			if (_mi->parent == NULL)				\
				return 0;					\
			if (_mi->siblings._el == &_mi->parent->children) {	\
				_mi = _mi->parent;				\
				goto up;					\
			}							\
			_mi = list_entry(_mi->siblings._el,			\
					struct mount_info, siblings);		\
		}								\
	} while (0)

#define MNT_WALK_NONE	0 &&


static int mnt_tree_for_each(struct mount_info *m,
		int (*fn)(struct mount_info *))
{
	MNT_TREE_WALK(m, next, fn, MNT_WALK_NONE);
}

static int mnt_tree_for_each_reverse(struct mount_info *m,
		int (*fn)(struct mount_info *))
{
	MNT_TREE_WALK(m, prev, MNT_WALK_NONE, fn);
}

static char *resolve_source(struct mount_info *mi)
{
	if (kdev_major(mi->s_dev) == 0)
		/*
		 * Anonymous block device. Kernel creates them for
		 * diskless mounts.
		 */
		return mi->source;

	pr_err("No device for %s mount\n", mi->mountpoint);
	return NULL;
}

static int do_new_mount(struct mount_info *mi)
{
	char *src;

	src = resolve_source(mi);
	if (!src)
		return -1;

	if (mount(src, mi->mountpoint, mi->fstype,
				mi->flags, mi->options) < 0) {
		pr_perror("Can't mount at %s", mi->mountpoint);
		return -1;
	}

	return 0;
}

static int do_bind_mount(struct mount_info *mi)
{
	pr_err("No bind mounts at %s\n", mi->mountpoint);
	return -1;
}

static inline int fsroot_mounted(struct mount_info *mi)
{
	return is_root(mi->root);
}

static int do_mount_one(struct mount_info *mi)
{
	if (!mi->parent)
		return 0;

	pr_debug("\tMounting %s @%s\n", mi->fstype, mi->mountpoint);

	if (fsroot_mounted(mi))
		return do_new_mount(mi);
	else
		return do_bind_mount(mi);
}

static int do_umount_one(struct mount_info *mi)
{
	if (!mi->parent)
		return 0;

	if (umount(mi->mountpoint)) {
		pr_perror("Can't umount at %s", mi->mountpoint);
		return -1;
	}

	pr_info("Umounted at %s\n", mi->mountpoint);
	return 0;
}

static int clean_mnt_ns(void)
{
	struct mount_info *pm;

	pr_info("Cleaning mount namespace\n");

	/*
	 * Mountinfos were collected at prepare stage
	 */

	pm = mnt_build_tree(mntinfo);
	if (!pm)
		return -1;

	return mnt_tree_for_each_reverse(pm, do_umount_one);
}

static int populate_mnt_ns(int ns_pid)
{
	MntEntry *me = NULL;
	int img, ret;
	struct mount_info *pms = NULL;

	pr_info("Populating mount namespace\n");

	img = open_image_ro(CR_FD_MOUNTPOINTS, ns_pid);
	if (img < 0)
		return -1;

	pr_debug("Reading mountpoint images\n");

	while (1) {
		struct mount_info *pm;

		ret = pb_read_eof(img, &me, mnt_entry);
		if (ret <= 0)
			break;

		ret = -1;
		pm = xmalloc(sizeof(*pm));
		if (!pm)
			break;

		mnt_entry_init(pm);

		pm->mnt_id		= me->mnt_id;
		pm->parent_mnt_id	= me->parent_mnt_id;
		pm->s_dev		= me->root_dev;
		pm->flags		= me->flags;

		/* FIXME: abort unsupported early */
		pm->fstype		= decode_fstype(me->fstype);

		pr_debug("\t\tGetting root for %d\n", pm->mnt_id);
		pm->root = xstrdup(me->root);
		if (!pm->root)
			return -1;

		pr_debug("\t\tGetting mpt for %d\n", pm->mnt_id);
		pm->mountpoint = xstrdup(me->mountpoint);
		if (!pm->mountpoint)
			return -1;

		pr_debug("\t\tGetting source for %d\n", pm->mnt_id);
		pm->source = xstrdup(me->source);
		if (!pm->source)
			return -1;

		pr_debug("\t\tGetting opts for %d\n", pm->mnt_id);
		pm->options = xstrdup(me->options);
		if (!pm->options)
			return -1;

		pr_debug("\tRead %d mp @ %s\n", pm->mnt_id, pm->mountpoint);
		pm->next = pms;
		pms = pm;
	}

	if (me)
		mnt_entry__free_unpacked(me, NULL);

	close(img);

	pms = mnt_build_tree(pms);
	if (!pms)
		return -1;

	return mnt_tree_for_each(pms, do_mount_one);
}

int prepare_mnt_ns(int ns_pid)
{
	int ret;

	pr_info("Restoring mount namespace\n");

	/*
	 * The new mount namespace is filled with the mountpoint
	 * clones from the original one. We have to umount them
	 * prior to recreating new ones.
	 */

	ret = clean_mnt_ns();
	if (!ret)
		ret = populate_mnt_ns(ns_pid);

	return ret;
}

void show_mountpoints(int fd, struct cr_options *o)
{
	pb_show_plain(fd, mnt_entry);
}
