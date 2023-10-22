#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sched.h>

#include "cr_options.h"
#include "util.h"
#include "util-pie.h"
#include "log.h"
#include "plugin.h"
#include "filesystems.h"
#include "mount.h"
#include "mount-v2.h"
#include "pstree.h"
#include "image.h"
#include "namespaces.h"
#include "protobuf.h"
#include "fs-magic.h"
#include "path.h"
#include "files-reg.h"
#include "external.h"
#include "clone-noasan.h"
#include "fdstore.h"
#include "rst-malloc.h"

#include "images/mnt.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "mnt: "

#define CONTEXT_OPT "context="

/* A helper mount_info entry for the roots yard */
struct mount_info *root_yard_mp = NULL;

static LIST_HEAD(delayed_unbindable);

char *service_mountpoint(const struct mount_info *mi)
{
	if (!opts.mntns_compat_mode && opts.mode == CR_RESTORE) {
		BUG_ON(!mi->plain_mountpoint);
		return mi->plain_mountpoint;
	}
	return mi->mountpoint;
}

int ext_mount_add(char *key, char *val)
{
	cleanup_free char *e_str = NULL;

	e_str = xmalloc(strlen(key) + strlen(val) + 8);
	if (!e_str)
		return -1;

	/*
	 * On dump the key is the mountpoint as seen from the mount
	 * namespace, the val is some name that will be put into image
	 * instead of the mount point's root path.
	 *
	 * On restore the key is the name from the image (the one
	 * mentioned above) and the val is the path in criu's mount
	 * namespace that will become the mount point's root, i.e. --
	 * be bind mounted to the respective mountpoint.
	 */

	sprintf(e_str, "mnt[%s]:%s", key, val);
	return add_external(e_str);
}

int ext_mount_parse_auto(char *key)
{
	opts.autodetect_ext_mounts = true;

	if (*key == ':') {
		key++;
		if (*key == 'm')
			opts.enable_external_masters = true;
		else if (*key == 's')
			opts.enable_external_sharing = true;
		else if (*key != '\0')
			return -1;
	}

	return 0;
}

/* Lookup ext_mount by key field */
static char *ext_mount_lookup(char *key)
{
	char *v;
	int len = strlen(key);
	char mkey[len + 6];

	sprintf(mkey, "mnt[%s]", key);
	v = external_lookup_by_key(mkey);
	if (IS_ERR(v))
		v = NULL;

	return v;
}

/*
 * Single linked list of mount points get from proc/images
 */
struct mount_info *mntinfo;

static void mntinfo_add_list(struct mount_info *new)
{
	if (!mntinfo)
		mntinfo = new;
	else {
		struct mount_info *pm;

		/* Add to the tail. (FIXME -- make O(1) ) */
		for (pm = mntinfo; pm->next != NULL; pm = pm->next)
			;
		pm->next = new;
	}
}

void mntinfo_add_list_before(struct mount_info **head, struct mount_info *new)
{
	new->next = *head;
	*head = new;
}

static struct mount_info *__lookup_overlayfs(struct mount_info *list, char *rpath, unsigned int st_dev,
					     unsigned int st_ino, unsigned int mnt_id)
{
	/*
	 * Goes through all entries in the mountinfo table
	 * looking for a mount point that contains the file specified
	 * in rpath. Uses the device number st_dev and the inode number st_ino
	 * to make sure the file is correct.
	 */
	struct mount_info *mi_ret = NULL;
	struct mount_info *m;
	int mntns_root = -1;

	for (m = list; m != NULL; m = m->next) {
		struct stat f_stat;
		int ret_stat;

		if (m->fstype->code != FSTYPE__OVERLAYFS)
			continue;

		/*
		 * We need the mntns root fd of the process to be dumped,
		 * to make sure we stat the correct file
		 */
		if (mntns_root == -1) {
			mntns_root = __mntns_get_root_fd(root_item->pid->real);
			if (mntns_root < 0) {
				pr_err("Unable to get the root file descriptor of pid %d\n", root_item->pid->real);
				return ERR_PTR(-ENOENT);
			}
		}

		/*
		 * Concatenates m->ns_mountpoint with rpath and attempts
		 * to stat the resulting path at mntns_root
		 */
		if (is_root_mount(m)) {
			ret_stat = fstatat(mntns_root, rpath, &f_stat, 0);
		} else {
			char _full_path[PATH_MAX];
			int n = snprintf(_full_path, PATH_MAX, "%s/%s", m->ns_mountpoint, rpath);

			if (n >= PATH_MAX) {
				pr_err("Not enough space to concatenate %s and %s\n", m->ns_mountpoint, rpath);
				return ERR_PTR(-ENOSPC);
			}
			ret_stat = fstatat(mntns_root, _full_path, &f_stat, 0);
		}

		if (ret_stat == 0 && st_dev == f_stat.st_dev && st_ino == f_stat.st_ino)
			mi_ret = m;
	}

	return mi_ret;
}

/*
 * Looks up the mnt_id and path of a file in an overlayFS directory.
 *
 * This is useful in order to fix the OverlayFS bug present in the
 * Linux Kernel before version 4.2. See fixup_overlayfs for details.
 *
 * We first check to see if the mnt_id and st_dev numbers currently match
 * some entry in the mountinfo table. If so, we already have the correct mnt_id
 * and no fixup is needed.
 *
 * Then we proceed to see if there are any overlayFS mounted directories
 * in the mountinfo table. If so, we concatenate the mountpoint with the
 * name of the file, and stat the resulting path to check if we found the
 * correct device id and node number. If that is the case, we update the
 * mount id and link variables with the correct values.
 */
struct mount_info *lookup_overlayfs(char *rpath, unsigned int st_dev, unsigned int st_ino, unsigned int mnt_id)
{
	struct mount_info *m;

	/* If the mnt_id and device number match for some entry, no fixup is needed */
	for (m = mntinfo; m != NULL; m = m->next)
		if (st_dev == kdev_to_odev(m->s_dev) && mnt_id == m->mnt_id)
			return NULL;

	return __lookup_overlayfs(mntinfo, rpath, st_dev, st_ino, mnt_id);
}

static struct mount_info *__lookup_mnt_id(struct mount_info *list, int id)
{
	struct mount_info *m;

	for (m = list; m != NULL; m = m->next)
		if (m->mnt_id == id)
			return m;

	return NULL;
}

struct mount_info *lookup_mnt_id(unsigned int id)
{
	return __lookup_mnt_id(mntinfo, id);
}

struct mount_info *lookup_mnt_sdev(unsigned int s_dev)
{
	struct mount_info *m;

	for (m = mntinfo; m != NULL; m = m->next)
		/*
		 * We should not provide notdir bindmounts to open_mount as
		 * opening them can fail/hang for binds of unix sockets/fifos
		 */
		if (m->s_dev == s_dev && mnt_is_dir(m))
			return m;

	pr_err("Unable to find suitable mount point for s_dev %x\n", s_dev);
	return NULL;
}

static struct mount_info *mount_resolve_path(struct mount_info *mntinfo_tree, const char *path)
{
	size_t pathlen = strlen(path);
	struct mount_info *m = mntinfo_tree, *c;

	while (1) {
		list_for_each_entry(c, &m->children, siblings) {
			size_t n;

			n = strlen(c->ns_mountpoint + 1);
			if (n > pathlen)
				continue;

			if (strncmp(c->ns_mountpoint + 1, path, min(n, pathlen)))
				continue;
			if (n < pathlen && path[n] != '/')
				continue;

			m = c;
			break;
		}
		if (&c->siblings == &m->children)
			break;
	}

	pr_debug("Path `%s' resolved to `%s' mountpoint\n", path, m->ns_mountpoint);
	return m;
}

dev_t phys_stat_resolve_dev(struct ns_id *ns, dev_t st_dev, const char *path)
{
	struct mount_info *m;

	m = mount_resolve_path(ns->mnt.mntinfo_tree, path);
	/*
	 * BTRFS returns subvolume dev-id instead of
	 * superblock dev-id, in such case return device
	 * obtained from mountinfo (ie subvolume0).
	 */
	return strcmp(m->fstype->name, "btrfs") ? MKKDEV(major(st_dev), minor(st_dev)) : m->s_dev;
}

bool phys_stat_dev_match(dev_t st_dev, dev_t phys_dev, struct ns_id *ns, const char *path)
{
	if (st_dev == kdev_to_odev(phys_dev))
		return true;

	return phys_dev == phys_stat_resolve_dev(ns, st_dev, path);
}

/*
 * Compare super-blocks mounted at two places
 */
static bool mounts_sb_equal(struct mount_info *a, struct mount_info *b)
{
	if (a->s_dev != b->s_dev)
		return false;

	/*
	 * If one of compared mounts is external its mount info can have fstype
	 * and source fields changed by resolve_external_mounts() or
	 * try_resolve_ext_mount(), but we still want to detect bindmounts of
	 * this external mount, so let's skip source and fstype checks for it.
	 */
	if (!a->external && !b->external) {
		if (strcmp(a->source, b->source) != 0)
			return false;

		if (a->fstype != b->fstype)
			return false;

		if (a->fstype->sb_equal)
			return a->fstype->sb_equal(a, b);
	} else {
		if (a->fstype->sb_equal)
			return a->fstype->sb_equal(a, b);
		else if (b->fstype->sb_equal)
			return b->fstype->sb_equal(a, b);
	}

	if (strcmp(a->options, b->options))
		return false;

	return true;
}

/*
 * Compare superblocks AND the way they are mounted
 */
static bool mounts_equal(struct mount_info *a, struct mount_info *b)
{
	if (!mounts_sb_equal(a, b))
		return false;
	if (strcmp(a->root, b->root))
		return false;

	return true;
}

/*
 * mnt_roots is a temporary directory for restoring sub-trees of
 * non-root namespaces.
 */
char *mnt_roots;

static struct mount_info *mnt_build_ids_tree(struct mount_info *list)
{
	struct mount_info *m, *root = NULL;

	/*
	 * Just resolve the mnt_id:parent_mnt_id relations
	 */

	pr_debug("\tBuilding plain mount tree\n");
	for (m = list; m != NULL; m = m->next) {
		struct mount_info *parent;

		pr_debug("\t\tWorking on %d->%d\n", m->mnt_id, m->parent_mnt_id);

		if (m->mnt_id != m->parent_mnt_id)
			parent = __lookup_mnt_id(list, m->parent_mnt_id);
		else /* a circular mount reference. It's rootfs or smth like it. */
			parent = NULL;

		if (!parent) {
			/* Only a root mount can be without parent */
			if (!root && m->is_ns_root) {
				root = m;
				continue;
			}

			pr_err("No parent found for mountpoint %d (@%s)\n", m->mnt_id, m->ns_mountpoint);
			return NULL;
		}

		m->parent = parent;
		list_add_tail(&m->siblings, &parent->children);
	}

	if (!root) {
		pr_err("No root found for tree\n");
		return NULL;
	}

	return root;
}

static unsigned int mnt_depth(struct mount_info *m)
{
	unsigned int depth = 0;
	char *c;

	for (c = m->ns_mountpoint; *c != '\0'; c++)
		if (*c == '/')
			depth++;

	return depth;
}

static void __mnt_resort_children(struct mount_info *parent)
{
	LIST_HEAD(list);

	/*
	 * Put children mounts in an order they can be (u)mounted
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

	pr_info("\tResorting children of %d in mount order\n", parent->mnt_id);
	while (!list_empty(&parent->children)) {
		struct mount_info *m, *p;
		unsigned int depth;

		m = list_first_entry(&parent->children, struct mount_info, siblings);
		list_del(&m->siblings);

		depth = mnt_depth(m);
		list_for_each_entry(p, &list, siblings)
			if (mnt_depth(p) < depth)
				break;

		list_add_tail(&m->siblings, &p->siblings);
	}

	list_splice(&list, &parent->children);
}

static struct mount_info *mnt_subtree_next(struct mount_info *mi, struct mount_info *root);

static void resort_siblings(struct mount_info *root, void (*resort_children)(struct mount_info *))
{
	struct mount_info *mi = root;
	while (1) {
		/*
		 * Explanation: sorting the children of the tree like these is
		 * safe and does not break the tree search in mnt_subtree_next
		 * (DFS-next search), as we sort children before calling next
		 * on parent and thus before DFS-next ever touches them, so
		 * from the perspective of DFS-next all children look like they
		 * are already sorted.
		 */
		resort_children(mi);
		mi = mnt_subtree_next(mi, root);
		if (!mi)
			break;
	}
}

static void mnt_tree_show(struct mount_info *tree, int off)
{
	struct mount_info *m;

	pr_info("%*s[%s](%d->%d)\n", off, "", tree->ns_mountpoint, tree->mnt_id, tree->parent_mnt_id);

	list_for_each_entry(m, &tree->children, siblings)
		mnt_tree_show(m, off + 1);

	pr_info("%*s<--\n", off, "");
}

/* Returns -1 on error, 1 if external mount resolved, 0 otherwise */
static int try_resolve_ext_mount(struct mount_info *info)
{
	char devstr[64];

	/*
	 * Only allow mountpoint-external mounts in root mntns. Their lookup is
	 * based on mountpoint path, but in nested mntns we can have completely
	 * different mount tree and at same mountpoint we can have completely
	 * different mount.
	 */
	if (info->nsid->type == NS_ROOT) {
		char *ext;

		ext = ext_mount_lookup(info->ns_mountpoint + 1 /* trim the . */);
		if (ext) {
			pr_info("Found %s mapping for %s mountpoint\n", ext, info->ns_mountpoint);
			info->external = ext;
			return 1;
		}
	}

	snprintf(devstr, sizeof(devstr), "dev[%d/%d]", kdev_major(info->s_dev), kdev_minor(info->s_dev));

	if (info->fstype->code == FSTYPE__UNSUPPORTED && fsroot_mounted(info)) {
		char *val;

		val = external_lookup_by_key(devstr);
		if (!IS_ERR_OR_NULL(val)) {
			char *source;
			int len;

			pr_info("Found %s dev-mapping for %s(%d) mountpoint\n", val, info->ns_mountpoint, info->mnt_id);
			info->external = EXTERNAL_DEV_MOUNT;

			len = strlen(val) + sizeof("dev[]");
			source = xrealloc(info->source, len);
			if (source == NULL)
				return -1;

			snprintf(source, len, "dev[%s]", val);
			info->fstype = fstype_auto();
			BUG_ON(info->fstype->code != FSTYPE__AUTO);
			info->source = source;
			return 1;
		}
	}

	return 0;
}

/*
 * Find the mount_info from which the respective bind-mount
 * can be created. It can be either an FS-root mount, or the
 * root of the tree (the latter only if its root path is the
 * sub-path of the bind mount's root).
 */

static struct mount_info *find_fsroot_mount_for(struct mount_info *bm)
{
	struct mount_info *sm;

	list_for_each_entry(sm, &bm->mnt_bind, mnt_bind)
		if (fsroot_mounted(sm) || (sm->parent == root_yard_mp && strstartswith(bm->root, sm->root)))
			return sm;

	return NULL;
}

static bool mnt_needs_remap(struct mount_info *m)
{
	struct mount_info *t;

	if (!m->parent || m->parent == root_yard_mp)
		return false;

	list_for_each_entry(t, &m->parent->children, siblings) {
		if (m == t)
			continue;
		if (issubpath(t->ns_mountpoint, m->ns_mountpoint))
			return true;
	}

	/*
	 * If we are children-overmount and parent is remapped, we should be
	 * remapped too, else fixup_remap_mounts() won't be able to move parent
	 * to it's real place, it will move child instead.
	 */
	if (!strcmp(m->parent->ns_mountpoint, m->ns_mountpoint))
		return mnt_needs_remap(m->parent);

	return false;
}

static bool __mnt_is_external_bind(struct mount_info *mi, struct mount_info *bind)
{
	if (bind->external && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

/*
 * Say mount is external if it was explicitly specified as an external or it
 * can be bind-mounted from such an explicit external mount.
 */
struct mount_info *mnt_get_external_bind(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __mnt_is_external_bind);
}

bool mnt_is_external_bind(struct mount_info *mi)
{
	return mnt_get_external_bind(mi);
}

static bool __can_receive_master_from_external(struct mount_info *mi, struct mount_info *bind)
{
	if (mnt_is_nodev_external(bind) && bind->master_id == mi->master_id && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

static struct mount_info *can_receive_master_from_external(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __can_receive_master_from_external);
}

static bool __has_mounted_external_bind(struct mount_info *mi, struct mount_info *bind)
{
	if (bind->external && bind->mounted && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

bool has_mounted_external_bind(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __has_mounted_external_bind);
}

bool rst_mnt_is_root(struct mount_info *mi)
{
	return (mi->is_ns_root && mi->nsid->id == root_item->ids->mnt_ns_id);
}

static bool __mnt_is_root_bind(struct mount_info *mi, struct mount_info *bind)
{
	if (rst_mnt_is_root(bind) && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

struct mount_info *mnt_get_root_bind(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __mnt_is_root_bind);
}

bool mnt_is_root_bind(struct mount_info *mi)
{
	return mnt_get_root_bind(mi);
}

static bool __can_receive_master_from_root(struct mount_info *mi, struct mount_info *bind)
{
	if (rst_mnt_is_root(bind) && bind->master_id == mi->master_id && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

static struct mount_info *can_receive_master_from_root(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __can_receive_master_from_root);
}

static bool __mnt_is_external_bind_nodev(struct mount_info *mi, struct mount_info *bind)
{
	if (bind->external && !mnt_is_dev_external(bind) && is_sub_path(mi->root, bind->root))
		return true;

	return false;
}

struct mount_info *mnt_get_external_bind_nodev(struct mount_info *mi)
{
	return mnt_bind_pick(mi, __mnt_is_external_bind_nodev);
}

/*
 * Having two children with same mountpoint is unsupported. That can happen in
 * case of mount propagation inside of shared mounts, in that case it is hard
 * to find out mount propagation siblings and which of these mounts is above
 * (visible) and which is beneath (hidden). It would've broken mount restore
 * order in can_mount_now and also visibility assumptions in open_mountpoint.
 *
 * Anyway after kernel v4.11 such mounts will be impossible.
 */
static int validate_children_collision(struct mount_info *mnt)
{
	struct mount_info *chi, *chj;

	list_for_each_entry(chi, &mnt->children, siblings) {
		list_for_each_entry(chj, &mnt->children, siblings) {
			if (chj == chi)
				break;
			if (!strcmp(chj->ns_mountpoint, chi->ns_mountpoint)) {
				pr_err("Mount %d has two children with same "
				       "mountpoint: %d %d\n",
				       mnt->mnt_id, chj->mnt_id, chi->mnt_id);
				return -1;
			}
		}
	}
	return 0;
}

int validate_mounts(struct mount_info *info, bool for_dump)
{
	struct mount_info *m, *t;

	for (m = info; m; m = m->next) {
		if (validate_children_collision(m))
			return -1;

		if (mnt_is_external_bind(m))
			continue;

		if (mnt_is_root_bind(m))
			continue;

		/*
		 * Mountpoint can point to / of an FS. In that case this FS
		 * should be of some known type so that we can just mount one.
		 *
		 * Otherwise it's a bindmount mountpoint and we try to find
		 * what fsroot mountpoint it's bound to. If this point is the
		 * root mount, the path to bindmount root should be accessible
		 * form the rootmount path (the strstartswith check in the
		 * else branch below).
		 */

		if (fsroot_mounted(m)) {
			if (m->fstype->code == FSTYPE__UNSUPPORTED) {
				pr_err("FS mnt %s dev %#x root %s unsupported id %d\n", m->ns_mountpoint, m->s_dev,
				       m->root, m->mnt_id);
				return -1;
			}
		} else {
			t = find_fsroot_mount_for(m);
			if (!t) {
				int ret;

				/*
				 * No root-mount found for this bind and it's neither
				 * marked nor auto-resolved as external one. So last
				 * chance not to fail is to talk to plugins.
				 */

				if (for_dump) {
					ret = run_plugins(DUMP_EXT_MOUNT, m->ns_mountpoint, m->mnt_id);
					if (ret == 0)
						m->need_plugin = true;
				} else
					/*
					 * Plugin should take care of this one
					 * in restore_ext_mount, or do_bind_mount
					 * will mount it as external
					 */
					ret = m->need_plugin ? 0 : -ENOTSUP;

				if (ret < 0) {
					if (ret == -ENOTSUP)
						pr_err("%d:%s doesn't have a proper root mount\n", m->mnt_id,
						       m->ns_mountpoint);
					return -1;
				}
			}
		}
	}

	return 0;
}

static struct mount_info *find_best_external_match(struct mount_info *list, struct mount_info *info)
{
	struct mount_info *it, *candidate = NULL;

	for (it = list; it; it = it->next) {
		if (!mounts_sb_equal(info, it))
			continue;

		/*
		 * This means we have a situation like:
		 *
		 * root@criu:~# mount --bind bind1/subdir/ bind2
		 * root@criu:~# mount --bind bind1/ bind3
		 *
		 * outside the container, and bind1 is directly bind mounted
		 * inside the container. mounts_equal() considers these mounts
		 * equal for bind purposes, but their roots are different, and
		 * we want to match the one with the right root.
		 */
		if (!issubpath(info->root, it->root))
			continue;

		candidate = it;

		/*
		 * Consider the case of:
		 *
		 * mount /xxx
		 * mount --bind /xxx /yyy
		 * mount --make-shared /yyy
		 * mount --bind /xxx /zzz
		 * mount --make-shared /zzz
		 * bind mount a shared mount into the namespace
		 *
		 * Here, we want to return the /right/ mount, not just a mount
		 * that's equal. However, in the case:
		 *
		 * bind mount a shared mount into the namespace
		 * inside the namespace, remount MS_PRIVATE
		 * inside the namespace, remount MS_SHARED
		 *
		 * there will be no external mount with matching sharing
		 * because the sharing is only internal; we still want to bind
		 * mount from this mountinfo so we should return it, but we
		 * should make the sharing namespace private after that bind
		 * mount.
		 *
		 * Below are the cases where we found an exact match.
		 */
		if (info->flags & MS_SHARED && info->shared_id == it->shared_id)
			return candidate;

		if (info->flags & MS_SLAVE && info->master_id == it->shared_id)
			return candidate;
	}

	return candidate;
}

static struct ns_id *find_ext_ns_id(void)
{
	struct ns_id *ns;

	for (ns = ns_ids; ns->next; ns = ns->next)
		if (ns->type == NS_CRIU && ns->nd == &mnt_ns_desc) {
			if (!ns->mnt.mntinfo_list && !collect_mntinfo(ns, false))
				break;
			return ns;
		}

	pr_err("Failed to find criu pid's mount ns\n");
	return NULL;
}

static int resolve_external_mounts(struct mount_info *info)
{
	struct ns_id *ext_ns = NULL;
	struct mount_info *m;

	if (opts.autodetect_ext_mounts) {
		ext_ns = find_ext_ns_id();
		if (!ext_ns)
			return -1;
	}

	for (m = info; m; m = m->next) {
		int ret;
		char *p, *cut_root;
		struct mount_info *match;

		if (m->parent == NULL || m->is_ns_root)
			continue;

		ret = try_resolve_ext_mount(m);
		if (ret < 0)
			return ret;
		if (ret == 1 || !ext_ns)
			continue;

		match = find_best_external_match(ext_ns->mnt.mntinfo_list, m);
		if (!match)
			continue;

		if (m->flags & MS_SHARED) {
			if (!opts.enable_external_sharing)
				continue;

			if (m->shared_id != match->shared_id)
				m->internal_sharing = true;
		}

		if (m->flags & MS_SLAVE) {
			if (!opts.enable_external_masters)
				continue;

			/*
			 * In order to support something like internal slavery,
			 * we need to teach can_mount_now and do_mount_one
			 * about slavery relationships in external mounts. This
			 * seems like an uncommon case, so we punt for not.
			 */
			if (m->master_id != match->shared_id && m->master_id != match->master_id)
				continue;
		}

		cut_root = cut_root_for_bind(m->root, match->root);

		p = xsprintf("%s/%s", match->ns_mountpoint + 1, cut_root);
		if (!p)
			return -1;

		m->external = AUTODETECTED_MOUNT;

		/*
		 * Put the guessed name in source. It will be picked up
		 * as auto-root in get_mp_root() on restore.
		 */
		xfree(m->source);
		m->source = p;

		pr_info("autodetected external mount %s for %s(%d)\n", p, m->ns_mountpoint, m->mnt_id);
	}

	return 0;
}

static int root_path_from_parent(struct mount_info *m, char *buf, int size)
{
	bool head_slash = false, tail_slash = false;
	int p_len, m_len, len;

	if (!m->parent || m->parent == root_yard_mp)
		return -1;

	p_len = strlen(m->parent->ns_mountpoint);
	m_len = strlen(m->ns_mountpoint);

	len = snprintf(buf, size, "%s", m->parent->root);
	if (len >= size)
		return -1;

	BUG_ON(len <= 0);
	if (buf[len - 1] == '/')
		tail_slash = true;

	size -= len;
	buf += len;

	len = m_len - p_len;
	BUG_ON(len < 0);
	if (len) {
		if (m->ns_mountpoint[p_len] == '/')
			head_slash = true;

		len = snprintf(buf, size, "%s%s", (!tail_slash && !head_slash) ? "/" : "",
			       m->ns_mountpoint + p_len + (tail_slash && head_slash));
		if (len >= size)
			return -1;
	}

	return 0;
}

static int same_propagation_group(struct mount_info *a, struct mount_info *b)
{
	char root_path_a[PATH_MAX], root_path_b[PATH_MAX];

	/*
	 * If mounts are in same propagation group:
	 * 1) Their parents should be different
	 * 2) Their parents should be together in same shared group
	 */
	if (!a->parent || !b->parent || a->parent == b->parent || a->parent->shared_id != b->parent->shared_id)
		return 0;

	if (root_path_from_parent(a, root_path_a, PATH_MAX)) {
		pr_err("Failed to get root path for mount %d\n", a->mnt_id);
		return -1;
	}

	if (root_path_from_parent(b, root_path_b, PATH_MAX)) {
		pr_err("Failed to get root path for mount %d\n", b->mnt_id);
		return -1;
	}

	/*
	 * 3) Their mountpoints relative to the root of the superblock of their
	 * parent's share should be equal
	 */
	if (!strcmp(root_path_a, root_path_b))
		return 1;
	return 0;
}

/*
 * Note: Only valid if called consequently on all mounts in mntinfo list.
 *
 * Note: We may want to iterate over all bindmounts of some mount, and we would
 * use ->mnt_bind list for this, but iterating over ->mnt_bind list is
 * obviously meaningless before search_bindmounts had actually put bindmounts
 * in it. That's why we have ->mnt_bind_is_populated to protect from misuse of
 * ->mnt_bind. (As ->mnt_bind list can validly be empty when mount has no
 *  bindmounts we need separate field to indicate population.)
 */
static void __search_bindmounts(struct mount_info *mi)
{
	struct mount_info *t;

	if (mi->mnt_bind_is_populated)
		return;

	for (t = mi->next; t; t = t->next) {
		if (mounts_sb_equal(mi, t)) {
			list_add(&t->mnt_bind, &mi->mnt_bind);
			t->mnt_bind_is_populated = true;
			pr_debug("\t"
				 "The mount %3d is bind for %3d (@%s -> @%s)\n",
				 t->mnt_id, mi->mnt_id, t->ns_mountpoint, mi->ns_mountpoint);
		}
	}

	mi->mnt_bind_is_populated = true;
}

static void search_bindmounts(void)
{
	struct mount_info *mi;

	for (mi = mntinfo; mi; mi = mi->next)
		__search_bindmounts(mi);
}

struct mount_info *mnt_bind_pick(struct mount_info *mi, bool (*pick)(struct mount_info *mi, struct mount_info *bind))
{
	struct mount_info *bind;

	BUG_ON(!mi);

	if (pick(mi, mi))
		return mi;

	/*
	 * Shouldn't use mnt_bind list before it was populated in search_bindmounts
	 */
	BUG_ON(!mi->mnt_bind_is_populated);

	list_for_each_entry(bind, &mi->mnt_bind, mnt_bind)
		if (pick(mi, bind))
			return bind;

	return NULL;
}

static int resolve_shared_mounts(struct mount_info *info)
{
	struct mount_info *m, *t;

	/*
	 * If we have a shared mounts, both master
	 * slave targets are to be present in mount
	 * list, otherwise we can't be sure if we can
	 * recreate the scheme later on restore.
	 */
	for (m = info; m; m = m->next) {
		bool need_share, need_master;

		need_share = m->shared_id && list_empty(&m->mnt_share);
		need_master = m->master_id;

		pr_debug("Inspecting sharing on %2d shared_id %d master_id %d (@%s)\n", m->mnt_id, m->shared_id,
			 m->master_id, m->ns_mountpoint);

		for (t = info; t && (need_share || need_master); t = t->next) {
			if (t == m)
				continue;
			if (need_master && t->shared_id == m->master_id) {
				pr_debug("\t"
					 "The mount %3d is slave for %3d (@%s -> @%s)\n",
					 m->mnt_id, t->mnt_id, m->ns_mountpoint, t->ns_mountpoint);
				list_add(&m->mnt_slave, &t->mnt_slave_list);
				m->mnt_master = t;
				need_master = false;
			}

			/* Collect all mounts from this group */
			if (need_share && t->shared_id == m->shared_id) {
				pr_debug("\t"
					 "Mount %3d is shared with %3d group %3d (@%s -> @%s)\n",
					 m->mnt_id, t->mnt_id, m->shared_id, t->ns_mountpoint, m->ns_mountpoint);
				list_add(&t->mnt_share, &m->mnt_share);
			}
		}

		/*
		 * External master detected
		 */
		if (need_master) {
			if ((t = can_receive_master_from_external(m)) || (t = can_receive_master_from_root(m))) {
				pr_debug("Detected external slavery for %d via %d\n", m->mnt_id, t->mnt_id);
				if (m != t)
					list_add(&m->mnt_ext_slave, &t->mnt_ext_slave);
				continue;
			}

			pr_err("Mount %d %s (master_id: %d shared_id: %d) "
			       "has unreachable sharing. Try --enable-external-masters.\n",
			       m->mnt_id, m->ns_mountpoint, m->master_id, m->shared_id);
			return -1;
		}
	}

	/* Search propagation groups */
	for (m = info; m; m = m->next) {
		struct mount_info *sparent;

		if (!list_empty(&m->mnt_propagate))
			continue;

		if (!m->parent || !m->parent->shared_id)
			continue;

		list_for_each_entry(sparent, &m->parent->mnt_share, mnt_share) {
			struct mount_info *schild;

			list_for_each_entry(schild, &sparent->children, siblings) {
				int ret;

				ret = same_propagation_group(m, schild);
				if (ret < 0)
					return -1;
				else if (ret) {
					BUG_ON(!mounts_equal(m, schild));
					pr_debug("\tMount %3d is in same propagation group with %3d (@%s ~ @%s)\n",
						 m->mnt_id, schild->mnt_id, m->ns_mountpoint, schild->ns_mountpoint);
					list_add(&schild->mnt_propagate, &m->mnt_propagate);
				}
			}
		}
	}

	return 0;
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

	resort_siblings(tree, __mnt_resort_children);
	pr_info("Done:\n");
	mnt_tree_show(tree, 0);
	return tree;
}

int mnt_is_dir(struct mount_info *pm)
{
	int mntns_root;
	struct stat st;

	mntns_root = mntns_get_root_fd(pm->nsid);
	if (mntns_root < 0) {
		pr_warn("Can't get root fd of mntns for %d: %s\n", pm->mnt_id, strerror(errno));
		return 0;
	}

	if (fstatat(mntns_root, pm->ns_mountpoint, &st, 0)) {
		pr_warn("Can't fstatat on %s: %s\n", pm->ns_mountpoint, strerror(errno));
		return 0;
	}

	if (S_ISDIR(st.st_mode))
		return 1;
	return 0;
}

int __check_mountpoint_fd(struct mount_info *pm, int mnt_fd, bool parse_mountinfo)
{
	struct stat st;
	unsigned int dev;
	int ret;

	ret = fstat(mnt_fd, &st);
	if (ret < 0) {
		pr_perror("fstat(%s) failed", pm->ns_mountpoint);
		return -1;
	}

	if (pm->s_dev_rt == MOUNT_INVALID_DEV) {
		pr_err("Resolving over invalid device for %#x %s %s\n", pm->s_dev, pm->fstype->name, pm->ns_mountpoint);
		return -1;
	}

	dev = MKKDEV(major(st.st_dev), minor(st.st_dev));
	/*
	 * Always check for @s_dev_rt here, because the @s_dev
	 * from the image (in case of restore) has all rights
	 * to not match the device (say it's migrated and kernel
	 * allocates new device ID).
	 */
	if (dev != pm->s_dev_rt) {
		/*
		 * For btrfs device numbers in stat and mountinfo can be
		 * different, fallback to get_sdev_from_fd to get right dev.
		 */
		if (!strcmp(pm->fstype->name, "btrfs") && !get_sdev_from_fd(mnt_fd, &dev, parse_mountinfo) &&
		    dev == pm->s_dev_rt)
			return 0;

		pr_warn("The file system %#x %#x (%#x) %s %s is inaccessible\n", pm->s_dev, pm->s_dev_rt, dev,
		        pm->fstype->name, pm->ns_mountpoint);
		return -1;
	}

	return 0;
}

int check_mountpoint_fd(struct mount_info *pm, int mnt_fd)
{
	return __check_mountpoint_fd(pm, mnt_fd, false);
}

/*
 * mnt_fd is a file descriptor on the mountpoint, which is closed in an error case.
 * If mnt_fd is -1, the mountpoint will be opened by this function.
 */
int __open_mountpoint(struct mount_info *pm)
{
	int mntns_root, mnt_fd;

	mntns_root = mntns_get_root_fd(pm->nsid);
	if (mntns_root < 0)
		return -1;

	mnt_fd = openat(mntns_root, pm->ns_mountpoint, O_RDONLY);
	if (mnt_fd < 0) {
		pr_perror("Can't open %s", pm->ns_mountpoint);
		return -1;
	}

	if (check_mountpoint_fd(pm, mnt_fd)) {
		close(mnt_fd);
		return -1;
	}

	return mnt_fd;
}

int open_mount(unsigned int s_dev)
{
	struct mount_info *m;
	int mnt_fd;

	m = lookup_mnt_sdev(s_dev);
	if (!m)
		return -ENOENT;

	mnt_fd = __open_mountpoint(m);
	if (mnt_fd < 0)
		pr_err("Can't open mount %#x\n", s_dev);
	return mnt_fd;
}

/* Bind-mount a mount point in a temporary place without children */
static char *get_clean_mnt(struct mount_info *mi, char *mnt_path_tmp, char *mnt_path_root)
{
	char *mnt_path;

	mnt_path = mkdtemp(mnt_path_tmp);
	if (mnt_path == NULL && errno == ENOENT)
		mnt_path = mkdtemp(mnt_path_root);
	if (mnt_path == NULL) {
		pr_warn("Can't create a temporary directory: %s\n", strerror(errno));
		return NULL;
	}

	if (mount(mi->ns_mountpoint, mnt_path, NULL, MS_BIND, NULL)) {
		pr_perror("Can't bind-mount %d:%s to %s", mi->mnt_id, mi->ns_mountpoint, mnt_path);
		rmdir(mnt_path);
		return NULL;
	}

	return mnt_path;
}

static int get_clean_fd(struct mount_info *mi)
{
	char *mnt_path = NULL;
	char mnt_path_tmp[] = "/tmp/cr-tmpfs.XXXXXX";
	char mnt_path_root[] = "/cr-tmpfs.XXXXXX";
	int fd;

	mnt_path = get_clean_mnt(mi, mnt_path_tmp, mnt_path_root);
	if (!mnt_path)
		return -1;

	fd = open(mnt_path, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0) {
		pr_perror("Can't open directory %s", mnt_path);
	} else {
		if (__check_mountpoint_fd(mi, fd, true))
			goto err_close;
	}

	if (umount2(mnt_path, MNT_DETACH)) {
		pr_perror("Can't detach mount %s", mnt_path);
		goto err_close;
	}

	if (rmdir(mnt_path)) {
		pr_perror("Can't remove tmp dir %s", mnt_path);
		goto err_close;
	}

	return fd;
err_close:
	close_safe(&fd);
	return -1;
}

/*
 * Our children mount can have same mountpoint as it's parent,
 * call these - children-overmount.
 * Sibling mount's mountpoint can be a subpath of our mountpoint
 * call these - sibling-overmount.
 * In both above cases our mountpoint is not visible from the
 * root of our mount namespace as it is covered by other mount.
 * mnt_is_overmounted() checks if mount is not visible.
 */
bool mnt_is_overmounted(struct mount_info *mi)
{
	struct mount_info *t, *c, *m = mi;

	if (mi->is_overmounted != -1)
		goto exit;

	mi->is_overmounted = 0;

	while (m->parent) {
		if (mi->parent->is_overmounted == 1) {
			mi->is_overmounted = 1;
			goto exit;
		}

		/* Check there is no sibling-overmount */
		list_for_each_entry(t, &m->parent->children, siblings) {
			if (m == t)
				continue;
			if (issubpath(m->ns_mountpoint, t->ns_mountpoint)) {
				mi->is_overmounted = 1;
				goto exit;
			}
		}

		/*
		 * If parent has sibling-overmount we are not visible too,
		 * note that children-overmounts for parent are already
		 * checked as our sibling overmounts.
		 */
		m = m->parent;
	}

	/* Check there is no children-overmount */
	list_for_each_entry(c, &mi->children, siblings)
		if (!strcmp(c->ns_mountpoint, mi->ns_mountpoint)) {
			mi->is_overmounted = 1;
			goto exit;
		}

exit:
	return mi->is_overmounted;
}

static int __set_is_overmounted(struct mount_info *mi)
{
	/* coverity[check_return] */
	mnt_is_overmounted(mi);
	return 0;
}

/*
 * mnt_is_overmounted is intended to detect overmounts in original dumped mount
 * tree, so we pre-save it just after loading mount tree from images, so that
 * it does not mess up with any helper mounts or tree changes we can do.
 */
static void prepare_is_overmounted(void)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid; nsid = nsid->next) {
		struct mount_info *root;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		root = nsid->mnt.mntinfo_tree;

		BUG_ON(root->parent);
		mnt_tree_for_each(root, __set_is_overmounted);
	}
}

/*
 * __umount_children_overmounts() assumes that the mountpoint and
 * it's ancestors have no sibling-overmounts, so we can see children
 * of these mount. Unmount our children-overmounts now.
 */
static int __umount_children_overmounts(struct mount_info *mi)
{
	struct mount_info *c, *m = mi;

	/*
	 * Our children-overmount can itself have children-overmount
	 * which covers it, so find deepest children-overmount which
	 * is visible for us now.
	 */
again:
	list_for_each_entry(c, &m->children, siblings) {
		if (!strcmp(c->ns_mountpoint, m->ns_mountpoint)) {
			m = c;
			goto again;
		}
	}

	/* Unmout children-overmounts in the order of visibility */
	while (m != mi) {
		if (umount2(m->ns_mountpoint, MNT_DETACH)) {
			pr_perror("Unable to umount child-overmount %s", m->ns_mountpoint);
			return -1;
		}
		BUG_ON(!m->parent);
		m = m->parent;
	}

	return 0;
}

/* Makes the mountpoint visible except for children-overmounts. */
static int __umount_overmounts(struct mount_info *m)
{
	struct mount_info *t, *ovm;
	int ovm_len, ovm_len_min = 0;

	/* Root mount has no sibling-overmounts */
	if (!m->parent)
		return 0;

	/*
	 * If parent is sibling-overmounted we are not visible
	 * too, so first try to unmount overmounts for parent.
	 */
	if (__umount_overmounts(m->parent))
		return -1;

	/* Unmount sibling-overmounts in visibility order */
next:
	ovm = NULL;
	ovm_len = strlen(m->ns_mountpoint) + 1;
	list_for_each_entry(t, &m->parent->children, siblings) {
		if (m == t)
			continue;
		if (issubpath(m->ns_mountpoint, t->ns_mountpoint)) {
			int t_len = strlen(t->ns_mountpoint);

			if (t_len < ovm_len && t_len > ovm_len_min) {
				ovm = t;
				ovm_len = t_len;
			}
		}
	}

	if (ovm) {
		ovm_len_min = ovm_len;

		/* Our sibling-overmount can have children-overmount covering it */
		if (__umount_children_overmounts(ovm))
			return -1;

		if (umount2(ovm->ns_mountpoint, MNT_DETACH)) {
			pr_perror("Unable to umount %s", ovm->ns_mountpoint + 1);
			return -1;
		}

		goto next;
	}

	return 0;
}

/* Make our mountpoint fully visible */
static int umount_overmounts(struct mount_info *m)
{
	if (__umount_overmounts(m))
		return -1;

	if (__umount_children_overmounts(m))
		return -1;

	return 0;
}

struct clone_arg {
	struct mount_info *mi;
	int *fd;
};

/*
 * Get access to the mountpoint covered by overmounts
 * and open it's cleaned copy (without children mounts).
 */
int ns_open_mountpoint(void *arg)
{
	struct clone_arg *ca = arg;
	struct mount_info *mi = ca->mi;
	int *fd = ca->fd;

	/*
	 * We should enter user namespace owning mount namespace of our mount
	 * before creating helper mount namespace. Else all mounts in helper
	 * mount namespace will be locked (MNT_LOCKED) and we won't be able to
	 * unmount them (see CL_UNPRIVILEGED in sys_umount(), clone_mnt() and
	 * copy_mnt_ns() in linux kernel code).
	 */
	if ((root_ns_mask & CLONE_NEWUSER) && switch_ns(root_item->pid->real, &user_ns_desc, NULL) < 0)
		goto err;

	/*
	 * Create a helper mount namespace in which we can safely do unmounts
	 * without breaking dumping process' environment.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to unshare a mount namespace");
		goto err;
	}

	/* Remount all mounts as private to disable propagation */
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		pr_perror("Unable to remount");
		goto err;
	}

	if (umount_overmounts(mi))
		goto err;

	/*
	 * Save fd which we opened for parent due to CLONE_FILES flag
	 *
	 * Mount can still have children in it, but we don't need to clean it
	 * explicitly as when last process exits mntns all mounts in it are
	 * cleaned from their children, and we are exactly the last process.
	 */
	*fd = open(mi->ns_mountpoint, O_DIRECTORY | O_RDONLY);
	if (*fd < 0) {
		pr_perror("Unable to open %s(%d)", mi->ns_mountpoint, mi->mnt_id);
		goto err;
	}

	if (__check_mountpoint_fd(mi, *fd, true)) {
		close(*fd);
		goto err;
	}

	return 0;
err:
	return 1;
}

int open_mountpoint(struct mount_info *pm)
{
	int fd = -1, cwd_fd, ns_old = -1;

	/* No overmounts and children - the entire mount is visible */
	if (list_empty(&pm->children) && !mnt_is_overmounted(pm))
		return __open_mountpoint(pm);

	pr_info("Mount is not fully visible %s(%d)\n", pm->ns_mountpoint, pm->mnt_id);

	/*
	 * We do two things below:
	 * a) If mount has children mounts in it which partially cover it's
	 * content, to get access to the content we create a "private" copy of
	 * such a mount, bind-mounting mount w/o MS_REC in a temporary place.
	 * b) If mount is overmounted we create a private copy of it's mount
	 * namespace so that we can safely get rid of overmounts and get an
	 * access to the mount.
	 * In both cases we can't do the thing from criu's mount namespace, so
	 * we need to switch to mount's mount namespace, and later switch back.
	 */

	if (switch_mnt_ns(pm->nsid->ns_pid, &ns_old, &cwd_fd) < 0)
		goto err;

	if (!mnt_is_overmounted(pm)) {
		pr_info("\tmount has children %s(%d)\n", pm->ns_mountpoint, pm->mnt_id);
		fd = get_clean_fd(pm);
	}

	/*
	 * Mount is overmounted or probably we can't create a temporary
	 * directory for a cleaned mount
	 */
	if (fd < 0) {
		int pid, status;
		struct clone_arg ca = { .mi = pm, .fd = &fd };

		pr_info("\tmount is overmounted or has children %s(%d)\n", pm->ns_mountpoint, pm->mnt_id);

		/*
		 * We are overmounted - not accessible in a regular way. We
		 * need to clone "private" copy of mount's monut namespace and
		 * unmount all covering overmounts in it. We also need to enter
		 * user namespace owning these mount namespace just before that
		 * (see explanation in ns_open_mountpoint). Thus we also have
		 * to create helper process here as entering user namespace is
		 * irreversible operation.
		 */
		pid = clone_noasan(ns_open_mountpoint,
				   CLONE_VFORK | CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM,
				   &ca);
		if (pid == -1) {
			pr_perror("Can't clone helper process");
			goto err;
		}

		errno = 0;
		if (waitpid(pid, &status, __WALL) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
			pr_err("Can't wait or bad status: errno=%d, status=%d\n", errno, status);
			goto err;
		}
	}

	if (restore_mnt_ns(ns_old, &cwd_fd)) {
		ns_old = -1;
		goto err;
	}

	return fd < 0 ? __open_mountpoint(pm) : fd;
err:
	if (ns_old >= 0)
		/* coverity[check_return] */
		restore_mnt_ns(ns_old, &cwd_fd);
	close_safe(&fd);
	return -1;
}

/*
 * Helper for getting a path to mount's plain mountpoint
 */
char *get_plain_mountpoint(int mnt_id, char *name)
{
	static char tmp[PATH_MAX];
	int ret;

	if (!mnt_roots)
		return NULL;

	if (name)
		ret = snprintf(tmp, sizeof(tmp), "%s/mnt-%s", mnt_roots, name);
	else
		ret = snprintf(tmp, sizeof(tmp), "%s/mnt-%010d", mnt_roots, mnt_id);

	if (ret >= sizeof(tmp))
		return NULL;

	return xstrdup(tmp);
}

struct mount_info __maybe_unused *add_cr_time_mount(struct mount_info *root, char *fsname, const char *path,
						    unsigned int s_dev, bool rst)
{
	struct mount_info *mi, *t, *parent;
	bool add_slash = false;
	int len;

	mi = mnt_entry_alloc(rst);
	if (!mi)
		return NULL;

	len = strlen(root->mountpoint);
	/* It may be "./" or "./path/to/dir" */
	if (root->mountpoint[len - 1] != '/') {
		add_slash = true;
		len++;
	}

	mi->mountpoint = xmalloc(len + strlen(path) + 1);
	if (!mi->mountpoint)
		goto err;
	if (!rst)
		mi->ns_mountpoint = mi->mountpoint;
	if (!add_slash)
		sprintf(mi->mountpoint, "%s%s", root->mountpoint, path);
	else
		sprintf(mi->mountpoint, "%s/%s", root->mountpoint, path);
	if (rst) {
		mi->plain_mountpoint = get_plain_mountpoint(-1, "crtime");
		if (!mi->plain_mountpoint)
			goto err;
	}
	mi->mnt_id = HELPER_MNT_ID;
	mi->is_dir = true;
	mi->flags = mi->sb_flags = 0;
	mi->root = xstrdup("/");
	mi->fsname = xstrdup(fsname);
	mi->source = xstrdup(fsname);
	mi->options = xstrdup("");
	if (!mi->root || !mi->fsname || !mi->source || !mi->options)
		goto err;
	mi->fstype = find_fstype_by_name(fsname);

	mi->s_dev = mi->s_dev_rt = s_dev;

	parent = root;
	while (1) {
		list_for_each_entry(t, &parent->children, siblings) {
			if (strstartswith(service_mountpoint(mi), service_mountpoint(t))) {
				parent = t;
				break;
			}
		}
		if (&t->siblings == &parent->children)
			break;
	}

	mi->mnt_bind_is_populated = true;
	mi->is_overmounted = false;
	mi->nsid = parent->nsid;
	mi->parent = parent;
	mi->parent_mnt_id = parent->mnt_id;
	list_add(&mi->siblings, &parent->children);
	pr_info("Add cr-time mountpoint %s with parent %s(%u)\n", service_mountpoint(mi), service_mountpoint(parent),
		parent->mnt_id);
	return mi;

err:
	mnt_entry_free(mi);
	return NULL;
}

/*
 * Returns:
 *  0 - success
 * -1 - error
 *  1 - skip
 */
static __maybe_unused int mount_cr_time_mount(struct ns_id *ns, unsigned int *s_dev, const char *source,
					      const char *target, const char *type)
{
	int mnt_fd, cwd_fd, exit_code = -1;
	struct stat st;

	if (switch_mnt_ns(ns->ns_pid, &mnt_fd, &cwd_fd)) {
		pr_err("Can't switch mnt_ns\n");
		return -1;
	}

	if (mount(source, target, type, 0, NULL)) {
		switch (errno) {
		case EPERM:
		case EBUSY:
		case ENODEV:
		case ENOENT:
			pr_debug("Skipping %s as was unable to mount it: %s\n", type, strerror(errno));
			exit_code = 1;
			break;
		default:
			pr_perror("Unable to mount %s %s %s", type, source, target);
		}
		goto restore_ns;
	}

	if (stat(target, &st)) {
		pr_perror("Can't stat %s", target);
		goto restore_ns;
	}

	*s_dev = MKKDEV(major(st.st_dev), minor(st.st_dev));
	exit_code = 0;
restore_ns:
	if (restore_mnt_ns(mnt_fd, &cwd_fd))
		exit_code = -1;
	return exit_code;
}

static int dump_one_fs(struct mount_info *mi)
{
	struct mount_info *pm = mi;
	struct mount_info *t;
	bool first = true;

	if (mnt_is_root_bind(mi) || mi->need_plugin || mnt_is_external_bind(mi) || !mi->fstype->dump)
		return 0;

	/* mnt_bind is a cycled list, so list_for_each can't be used here. */
	for (; &pm->mnt_bind != &mi->mnt_bind || first; pm = list_entry(pm->mnt_bind.next, typeof(*pm), mnt_bind)) {
		int ret;

		first = false;

		if (!fsroot_mounted(pm))
			continue;

		ret = pm->fstype->dump(pm);
		if (ret == MNT_UNREACHABLE)
			continue;
		if (ret < 0)
			return ret;

		pm->dumped = true;
		list_for_each_entry(t, &pm->mnt_bind, mnt_bind)
			t->dumped = true;
		return 0;
	}

	pr_err("Unable to dump a file system for %d:%s\n", mi->mnt_id, mi->ns_mountpoint);
	return -1;
}

static int dump_one_mountpoint(struct mount_info *pm, struct cr_img *img)
{
	MntEntry me = MNT_ENTRY__INIT;

	pr_info("\t%d: %x:%s @ %s\n", pm->mnt_id, pm->s_dev, pm->root, pm->ns_mountpoint);

	me.fstype = pm->fstype->code;

	if (me.fstype == FSTYPE__AUTO)
		me.fsname = pm->fsname;

	if (!pm->dumped && dump_one_fs(pm))
		return -1;

	if (!mnt_is_external_bind(pm) && !fsroot_mounted(pm) && pm->fstype->check_bindmount &&
	    pm->fstype->check_bindmount(pm))
		return -1;

	if (pm->mnt_id == HELPER_MNT_ID) {
		pr_info("Skip dumping helper mountpoint: %s\n", pm->ns_mountpoint);
		return 0;
	}

	me.mnt_id = pm->mnt_id;
	me.root_dev = pm->s_dev;
	me.parent_mnt_id = pm->parent_mnt_id;
	me.flags = pm->flags;
	me.sb_flags = pm->sb_flags;
	me.has_sb_flags = true;
	me.mountpoint = pm->ns_mountpoint + 1;
	me.source = pm->source;
	me.options = pm->options;
	me.shared_id = pm->shared_id;
	me.has_shared_id = true;
	me.master_id = pm->master_id;
	me.has_master_id = true;
	if (pm->need_plugin) {
		me.has_with_plugin = true;
		me.with_plugin = true;
	}
	if (pm->deleted) {
		me.has_deleted = true;
		me.deleted = true;
	}

	if (pm->internal_sharing) {
		me.has_internal_sharing = true;
		me.internal_sharing = true;
	}

	if (pm->external)
		/*
		 * For external mount points dump the mapping's
		 * value, see collect_mnt_from_image -> get_mp_root
		 * for reverse mapping details.
		 */
		me.ext_key = pm->external;
	me.root = pm->root;

	if (pb_write_one(img, &me, PB_MNT))
		return -1;

	return 0;
}

static void free_mntinfo(struct mount_info *pms)
{
	while (pms) {
		struct mount_info *pm;

		pm = pms->next;
		mnt_entry_free(pms);
		pms = pm;
	}
}

struct mount_info *collect_mntinfo(struct ns_id *ns, bool for_dump)
{
	struct mount_info *pm;

	pm = parse_mountinfo(ns->ns_pid, ns, for_dump);
	if (!pm) {
		pr_err("Can't parse %d's mountinfo\n", ns->ns_pid);
		return NULL;
	}

	ns->mnt.mntinfo_tree = mnt_build_tree(pm);
	if (ns->mnt.mntinfo_tree == NULL)
		goto err;

	ns->mnt.mntinfo_list = pm;
	return pm;
err:
	free_mntinfo(pm);
	return NULL;
}

static int dump_mnt_ns(struct ns_id *ns, struct mount_info *pms)
{
	struct mount_info *pm;
	int ret = -1;
	struct cr_img *img;
	unsigned int ns_id = ns->id;

	pr_info("Dumping mountpoints\n");
	img = open_image(CR_FD_MNTS, O_DUMP, ns_id);
	if (!img)
		goto err;

	for (pm = pms; pm && pm->nsid == ns; pm = pm->next)
		if (dump_one_mountpoint(pm, img))
			goto err_i;

	ret = 0;
err_i:
	close_image(img);
err:
	return ret;
}

/*
 * _fn_f  - pre-order traversal function
 * _fn_r  - post-order traversal function
 * _plist - a postpone list. _el is added to this list, if _fn_f returns
 *	    a positive value, and all lower elements are not enumerated.
 */
#define MNT_TREE_WALK(_r, _el, _fn_f, _fn_r, _plist, _prgs)                                       \
	do {                                                                                      \
		struct mount_info *_mi = _r;                                                      \
                                                                                                  \
		while (1) {                                                                       \
			int ret;                                                                  \
                                                                                                  \
			list_del_init(&_mi->postpone);                                            \
                                                                                                  \
			ret = _fn_f(_mi);                                                         \
			if (ret < 0)                                                              \
				return -1;                                                        \
			else if (ret > 0) {                                                       \
				list_add_tail(&_mi->postpone, _plist);                            \
				goto up;                                                          \
			}                                                                         \
                                                                                                  \
			_prgs++;                                                                  \
                                                                                                  \
			if (!list_empty(&_mi->children)) {                                        \
				_mi = list_entry(_mi->children._el, struct mount_info, siblings); \
				continue;                                                         \
			}                                                                         \
		up:                                                                               \
			if (_fn_r(_mi))                                                           \
				return -1;                                                        \
			if (_mi == _r)                                                            \
				break;                                                            \
			if (_mi->siblings._el == &_mi->parent->children) {                        \
				_mi = _mi->parent;                                                \
				goto up;                                                          \
			}                                                                         \
			_mi = list_entry(_mi->siblings._el, struct mount_info, siblings);         \
		}                                                                                 \
	} while (0)

#define MNT_WALK_NONE 0 &&

int mnt_tree_for_each(struct mount_info *start, int (*fn)(struct mount_info *))
{
	struct mount_info *tmp;
	LIST_HEAD(postpone);
	LIST_HEAD(postpone2);
	int progress;

	pr_debug("Start with %d:%s\n", start->mnt_id, start->ns_mountpoint);
	list_add(&start->postpone, &postpone);

again:
	progress = 0;

	list_for_each_entry_safe(start, tmp, &postpone, postpone)
		MNT_TREE_WALK(start, next, fn, MNT_WALK_NONE, &postpone2, progress);

	if (!progress) {
		struct mount_info *m;

		pr_err("A few mount points can't be mounted\n");
		list_for_each_entry(m, &postpone2, postpone) {
			pr_err("%d:%d %s %s %s\n", m->mnt_id, m->parent_mnt_id, m->root, m->ns_mountpoint, m->source);
		}
		return -1;
	}

	list_splice_init(&postpone2, &postpone);

	if (!list_empty(&postpone))
		goto again;

	return 0;
}

static int mnt_tree_for_each_reverse(struct mount_info *m, int (*fn)(struct mount_info *))
{
	int progress = 0;

	MNT_TREE_WALK(m, prev, MNT_WALK_NONE, fn, (struct list_head *)NULL, progress);
	(void)progress; // Suppress -Wused-but-unset-variable for clang>=15

	return 0;
}

char *resolve_source(struct mount_info *mi)
{
	if (kdev_major(mi->s_dev) == 0)
		/*
		 * Anonymous block device. Kernel creates them for
		 * diskless mounts.
		 */
		return mi->source;

	/*
	 * FSTYPE__AUTO check is a fallback for old images which do not have
	 * explicit EXTERNAL_DEV_MOUNT mark, but still have "dev[key]" in source.
	 */
	if (mnt_is_dev_external(mi) || mi->fstype->code == FSTYPE__AUTO) {
		struct stat st;
		char *val;

		val = external_lookup_by_key(mi->source);
		if (!IS_ERR_OR_NULL(val))
			return val;

		if (!stat(mi->source, &st) && S_ISBLK(st.st_mode) && major(st.st_rdev) == kdev_major(mi->s_dev) &&
		    minor(st.st_rdev) == kdev_minor(mi->s_dev))
			return mi->source;
	}

	pr_err("No device for %s(%d) mount\n", mi->ns_mountpoint, mi->mnt_id);
	return NULL;
}

static int restore_shared_options(struct mount_info *mi, bool private, bool shared, bool slave)
{
	pr_debug("%d:%s private %d shared %d slave %d\n", mi->mnt_id, service_mountpoint(mi), private, shared, slave);

	if (mi->flags & MS_UNBINDABLE) {
		if (shared || slave) {
			pr_warn("%s has both unbindable and sharing, ignoring unbindable\n", service_mountpoint(mi));
		} else {
			if (!mnt_is_overmounted(mi)) {
				/* Someone may still want to bind from us, let them do it. */
				pr_debug("Temporary leave unbindable mount %s as private\n", service_mountpoint(mi));
				if (mount(NULL, service_mountpoint(mi), NULL, MS_PRIVATE, NULL)) {
					pr_perror("Unable to make %d private", mi->mnt_id);
					return -1;
				}
				list_add(&mi->mnt_unbindable, &delayed_unbindable);
				return 0;
			}
			if (mount(NULL, service_mountpoint(mi), NULL, MS_UNBINDABLE, NULL)) {
				pr_perror("Unable to make %d unbindable", mi->mnt_id);
				return -1;
			}
			return 0;
		}
	}

	if (private && mount(NULL, service_mountpoint(mi), NULL, MS_PRIVATE, NULL)) {
		pr_perror("Unable to make %d private", mi->mnt_id);
		return -1;
	}
	if (slave && mount(NULL, service_mountpoint(mi), NULL, MS_SLAVE, NULL)) {
		pr_perror("Unable to make %d slave", mi->mnt_id);
		return -1;
	}
	if (shared && mount(NULL, service_mountpoint(mi), NULL, MS_SHARED, NULL)) {
		pr_perror("Unable to make %d shared", mi->mnt_id);
		return -1;
	}

	return 0;
}

/*
 * Umount points, which are propagated in slave parents, because
 * we can't be sure, that they were inherited in a real life.
 */
static int umount_from_slaves(struct mount_info *mi)
{
	struct mount_info *t;
	char *mpath, buf[PATH_MAX];

	BUG_ON(mi->parent == root_yard_mp);

	list_for_each_entry(t, &mi->parent->mnt_slave_list, mnt_slave) {
		if (!t->mounted)
			continue;

		mpath = mnt_get_sibling_path(mi, t, buf, sizeof(buf));
		if (mpath == NULL)
			continue;

		pr_debug("\t\tUmount slave %s\n", mpath);
		if (umount(mpath) == -1) {
			pr_perror("Can't umount slave %s", mpath);
			return -1;
		}
	}

	return 0;
}

/*
 * If something is mounted in one shared point, it will be spread in
 * all other points from this shared group.
 *
 * Look at Documentation/filesystems/sharedsubtree.txt for more details
 */
static int propagate_siblings(struct mount_info *mi)
{
	struct mount_info *t;

	/*
	 * Find all mounts, which must be bind-mounted from this one
	 * to inherit shared group or master id
	 */
	list_for_each_entry(t, &mi->mnt_share, mnt_share) {
		if (t->mounted)
			continue;
		if (t->bind && t->bind->shared_id == t->shared_id)
			continue;
		pr_debug("\t\tBind share %s(%d)\n", t->ns_mountpoint, t->mnt_id);
		t->bind = mi;
		t->s_dev_rt = mi->s_dev_rt;
	}

	list_for_each_entry(t, &mi->mnt_slave_list, mnt_slave) {
		if (t->mounted || t->bind)
			continue;
		pr_debug("\t\tBind slave %s(%d)\n", t->ns_mountpoint, t->mnt_id);
		t->bind = mi;
		t->s_dev_rt = mi->s_dev_rt;
	}

	list_for_each_entry(t, &mi->mnt_ext_slave, mnt_ext_slave) {
		if (t->mounted || t->bind)
			continue;
		pr_debug("\t\tBind ext-slave %s(%d)\n", t->ns_mountpoint, t->mnt_id);
		t->bind = mi;
		t->s_dev_rt = mi->s_dev_rt;
	}

	return 0;
}

static int propagate_mount(struct mount_info *mi)
{
	struct mount_info *p;

	propagate_siblings(mi);

	if (!mi->parent || mi->parent == root_yard_mp)
		goto skip_parent;

	umount_from_slaves(mi);

	/* Mark mounts in propagation group mounted */
	list_for_each_entry(p, &mi->mnt_propagate, mnt_propagate) {
		/* Should not propagate the same mount twice */
		BUG_ON(p->mounted);
		pr_debug("\t\tPropagate %s(%d)\n", p->ns_mountpoint, p->mnt_id);

		/*
		 * When a mount is propagated, the result mount
		 * is always shared. If we want to get a private
		 * mount, we need to convert it.
		 */
		restore_shared_options(p, !p->shared_id, 0, 0);
		p->mounted = true;
		propagate_siblings(p);
		umount_from_slaves(p);
	}

skip_parent:
	/*
	 * FIXME Currently non-root mounts can be restored
	 * only if a proper root mount exists
	 */
	if (fsroot_mounted(mi) || mi->parent == root_yard_mp || mi->external) {
		struct mount_info *t;

		list_for_each_entry(t, &mi->mnt_bind, mnt_bind) {
			if (t->mounted)
				continue;
			if (t->bind)
				continue;
			if (t->master_id)
				continue;
			if (!issubpath(t->root, mi->root))
				continue;
			pr_debug("\t\tBind private %s(%d)\n", t->ns_mountpoint, t->mnt_id);
			t->bind = mi;
			t->s_dev_rt = mi->s_dev_rt;
		}
	}

	return 0;
}

int fetch_rt_stat(struct mount_info *m, const char *where)
{
	struct stat st;

	if (stat(where, &st)) {
		pr_perror("Can't stat on %s", where);
		return -1;
	}

	m->s_dev_rt = MKKDEV(major(st.st_dev), minor(st.st_dev));
	return 0;
}

int do_simple_mount(struct mount_info *mi, const char *src, const char *fstype, unsigned long mountflags)
{
	int ret = mount(src, service_mountpoint(mi), fstype, mountflags, mi->options);
	if (ret)
		pr_perror("Unable to mount %s %s (id=%d)", src, service_mountpoint(mi), mi->mnt_id);
	return ret;
}

char *mnt_fsname(struct mount_info *mi)
{
	if (mi->fstype->code == FSTYPE__AUTO)
		return mi->fsname;
	return mi->fstype->name;
}

static int userns_mount(char *src, void *args, int fd, pid_t pid)
{
	unsigned long flags = *(unsigned long *)args;
	int rst = -1, err = -1;
	char target[PSFDS];

	snprintf(target, sizeof(target), "/proc/self/fd/%d", fd);

	if (pid != getpid() && switch_ns(pid, &mnt_ns_desc, &rst))
		return -1;

	err = mount(src, target, NULL, flags, NULL);
	if (err)
		pr_perror("Unable to mount %s", target);

	if (rst >= 0 && restore_ns(rst, &mnt_ns_desc))
		return -1;

	return err;
}

int apply_sb_flags(void *args, int fd, pid_t pid)
{
	return userns_mount(NULL, args, fd, pid);
}

int mount_root(void *args, int fd, pid_t pid)
{
	return userns_mount(opts.root, args, fd, pid);
}

static int do_new_mount(struct mount_info *mi)
{
	unsigned long sflags = mi->sb_flags;
	unsigned long mflags = mi->flags & (~MS_PROPAGATE);
	char *src;
	struct fstype *tp = mi->fstype;
	bool remount_ro = (tp->restore && mi->sb_flags & MS_RDONLY);
	mount_fn_t do_mount = (tp->mount) ? tp->mount : do_simple_mount;

	src = resolve_source(mi);
	if (!src)
		return -1;

	/* Merge superblock and mount flags if it's possible */
	if (!(mflags & ~MS_MNT_KNOWN_FLAGS) && !((sflags ^ mflags) & MS_RDONLY)) {
		sflags |= mflags;
		mflags = 0;
	}

	if (remount_ro)
		sflags &= ~MS_RDONLY;

	if (do_mount(mi, src, mnt_fsname(mi), sflags) < 0) {
		pr_perror("Can't mount at %s", service_mountpoint(mi));
		return -1;
	}

	if (tp->restore && tp->restore(mi))
		return -1;

	if (remount_ro) {
		int fd;

		fd = open(service_mountpoint(mi), O_PATH);
		if (fd < 0) {
			pr_perror("Unable to open %s", service_mountpoint(mi));
			return -1;
		}
		sflags |= MS_RDONLY | MS_REMOUNT;
		if (userns_call(apply_sb_flags, 0, &sflags, sizeof(sflags), fd)) {
			pr_err("Unable to apply mount flags %d for %s\n", mi->sb_flags, service_mountpoint(mi));
			close(fd);
			return -1;
		}
		close(fd);
	}

	if (mflags && mount(NULL, service_mountpoint(mi), NULL, MS_REMOUNT | MS_BIND | mflags, NULL)) {
		pr_perror("Unable to apply bind-mount options");
		return -1;
	}

	/*
	 * A slave should be mounted from do_bind_mount().
	 * Look at can_mount_now() for details.
	 */
	BUG_ON(mi->master_id);
	if (restore_shared_options(mi, !mi->shared_id, mi->shared_id, 0))
		return -1;

	mi->mounted = true;

	return 0;
}

int restore_ext_mount(struct mount_info *mi)
{
	int ret;

	pr_debug("Restoring external bind mount %s\n", service_mountpoint(mi));
	ret = run_plugins(RESTORE_EXT_MOUNT, mi->mnt_id, service_mountpoint(mi), "/", NULL);
	if (ret)
		pr_err("Can't restore ext mount (%d)\n", ret);
	return ret;
}

static char mnt_clean_path[] = "/tmp/cr-tmpfs.XXXXXX";

static int mount_clean_path(void)
{
	/*
	 * To make a bind mount, we need to have access to a source directory,
	 * which can be over-mounted. The idea is to mount a source mount in
	 * an intermediate place without MS_REC and then create a target mounts.
	 * This intermediate place should be a private mount to not affect
	 * properties of the source mount.
	 */
	if (mkdtemp(mnt_clean_path) == NULL) {
		pr_perror("Unable to create a temporary directory");
		return -1;
	}

	if (mount(mnt_clean_path, mnt_clean_path, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to mount tmpfs into %s", mnt_clean_path);
		return -1;
	}

	if (mount(NULL, mnt_clean_path, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Unable to mark %s as private", mnt_clean_path);
		return -1;
	}

	return 0;
}

static int umount_clean_path(void)
{
	if (umount2(mnt_clean_path, MNT_DETACH)) {
		pr_perror("Unable to umount %s", mnt_clean_path);
		return -1;
	}

	if (rmdir(mnt_clean_path)) {
		pr_perror("Unable to remove %s", mnt_clean_path);
	}

	return 0;
}

static int do_bind_mount(struct mount_info *mi)
{
	char mnt_fd_path[PSFDS];
	char *root, *cut_root, rpath[PATH_MAX];
	unsigned long mflags;
	int exit_code = -1, mp_len;
	bool shared = false;
	bool master = false;
	bool priv = false;
	char *mnt_path = NULL;
	struct stat st;
	bool umount_mnt_path = false;
	struct mount_info *c;

	if (mi->need_plugin) {
		if (restore_ext_mount(mi))
			return -1;
		goto out;
	}

	if (mnt_is_nodev_external(mi)) {
		/*
		 * We have / pointing to criu's ns root still,
		 * so just use the mapping's path. The mountpoint
		 * is tuned in collect_mnt_from_image to refer
		 * to proper location in the namespace we restore.
		 */
		root = mi->external;
		priv = !mi->master_id && (mi->internal_sharing || !mi->shared_id);
		goto do_bind;
	}

	shared = mi->shared_id && mi->shared_id == mi->bind->shared_id;
	master = mi->master_id && mi->master_id == mi->bind->master_id;
	priv = !mi->master_id && !shared;
	cut_root = cut_root_for_bind(mi->root, mi->bind->root);

	/* Mount private can be initialized on mount() callback, which is
	 * called only once.
	 * It have to be copied to all it's sibling structures to provide users
	 * of it with actual data.
	 */
	mi->private = mi->bind->private;

	mnt_path = service_mountpoint(mi->bind);

	/* Access a mount by fd if service_mountpoint(mi->bind) is overmounted */
	if (mi->bind->fd >= 0) {
		snprintf(mnt_fd_path, sizeof(mnt_fd_path), "/proc/self/fd/%d", mi->bind->fd);
		mnt_path = mnt_fd_path;
	}

	if (cut_root[0] == 0) /* This case is handled by mi->bind->fd */
		goto skip_overmount_check;

	/*
	 * The target path may be over-mounted by one of child mounts
	 * and we need to create a new bind-mount to get access to the path.
	 */
	mp_len = strlen(service_mountpoint(mi->bind));
	if (mp_len > 1) /* skip a joining / if service_mountpoint(mi->bind) isn't "/" */
		mp_len++;

	list_for_each_entry(c, &mi->bind->children, siblings) {
		if (!c->mounted)
			continue;
		if (issubpath(cut_root, service_mountpoint(c) + mp_len))
			break; /* a source path is overmounted */
	}

	if (&c->siblings != &mi->bind->children) {
		/* Get a copy of mi->bind without child mounts */
		if (mount(mnt_path, mnt_clean_path, NULL, MS_BIND, NULL)) {
			pr_perror("Unable to bind-mount %s to %s", mnt_path, mnt_clean_path);
			return -1;
		}
		mnt_path = mnt_clean_path;
		umount_mnt_path = true;
	}

	if (mnt_path == NULL)
		return -1;

skip_overmount_check:
	snprintf(rpath, sizeof(rpath), "%s/%s", mnt_path, cut_root);
	root = rpath;
do_bind:
	pr_info("\tBind %s to %s\n", root, service_mountpoint(mi));

	if (unlikely(mi->deleted)) {
		if (stat(service_mountpoint(mi), &st)) {
			pr_perror("Can't fetch stat on %s", service_mountpoint(mi));
			goto err;
		}

		if (S_ISDIR(st.st_mode)) {
			if (mkdir(root, (st.st_mode & ~S_IFMT))) {
				pr_perror("Can't re-create deleted directory %s", root);
				goto err;
			}
		} else if (S_ISREG(st.st_mode)) {
			int fd = open(root, O_WRONLY | O_CREAT | O_EXCL, st.st_mode & ~S_IFMT);
			if (fd < 0) {
				pr_perror("Can't re-create deleted file %s", root);
				goto err;
			}
			close(fd);
		} else {
			pr_err("Unsupported st_mode 0%o deleted root %s\n", (int)st.st_mode, root);
			goto err;
		}
	}

	if (mount(root, service_mountpoint(mi), NULL, MS_BIND | (mi->flags & MS_REC), NULL) < 0) {
		pr_perror("Can't bind-mount at %s", service_mountpoint(mi));
		goto err;
	}

	mflags = mi->flags & (~MS_PROPAGATE);
	if (!mi->bind || mflags != (mi->bind->flags & (~MS_PROPAGATE)))
		if (mount(NULL, service_mountpoint(mi), NULL, MS_BIND | MS_REMOUNT | mflags, NULL)) {
			pr_perror("Can't re-mount at %s", service_mountpoint(mi));
			goto err;
		}

	if (unlikely(mi->deleted)) {
		if (S_ISDIR(st.st_mode)) {
			if (rmdir(root)) {
				pr_perror("Can't remove deleted directory %s", root);
				goto err;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (unlink(root)) {
				pr_perror("Can't unlink deleted file %s", root);
				goto err;
			}
		}
	}
out:
	/*
	 * shared - the mount is in the same shared group with mi->bind
	 * mi->shared_id && !shared - create a new shared group
	 */
	if (restore_shared_options(mi, priv, mi->shared_id && !shared, mi->master_id && !master))
		goto err;

	mi->mounted = true;
	exit_code = 0;
err:
	if (umount_mnt_path) {
		/*
		 * If mnt_path was shared, a new mount may be propagated
		 * into it.
		 */
		if (mount(NULL, mnt_path, NULL, MS_PRIVATE, NULL)) {
			pr_perror("Unable to make %s private", mnt_path);
			return -1;
		}
		if (umount2(mnt_path, MNT_DETACH)) {
			pr_perror("Unable to umount %s", mnt_path);
			return -1;
		}
	}
	return exit_code;
}

static bool can_mount_now(struct mount_info *mi)
{
	struct mount_info *ext;

	if (rst_mnt_is_root(mi)) {
		pr_debug("%s: true as %d is mntns root\n", __func__, mi->mnt_id);
		return true;
	}

	/* Parent should be mounted already, that's how mnt_tree_for_each works */
	BUG_ON(mi->parent && !mi->parent->mounted);

	if (mnt_is_nodev_external(mi))
		goto shared;

	if (!mi->bind && !mi->external && (ext = mnt_get_external_bind(mi)) && !has_mounted_external_bind(mi)) {
		pr_debug("%s: false as %d's external %d is not mounted\n", __func__, mi->mnt_id, ext->mnt_id);
		return false;
	}

	/*
	 * We're the slave peer:
	 *   - Make sure the master peer is already mounted
	 *   - Make sure all children of master's share are
	 *   mounted as well to eliminate mounts duplications
	 */
	if (mi->mnt_master) {
		struct mount_info *c, *s;

		if (mi->bind == NULL) {
			pr_debug("%s: false as %d is slave with unmounted master %d\n", __func__, mi->mnt_id,
				 mi->mnt_master->mnt_id);
			return false;
		}

		list_for_each_entry(c, &mi->mnt_master->children, siblings) {
			if (!c->mounted) {
				pr_debug("%s: false as %d is slave with unmounted master's children %d\n", __func__,
					 mi->mnt_id, c->mnt_id);
				return false;
			}
		}

		list_for_each_entry(s, &mi->mnt_master->mnt_share, mnt_share) {
			list_for_each_entry(c, &s->children, siblings) {
				if (!c->mounted) {
					pr_debug("%s: false as %d is slave with unmounted children of master's share\n",
						 __func__, mi->mnt_id);
					return false;
				}
			}
		}
	}

	if (!fsroot_mounted(mi) && (mi->bind == NULL && !mi->need_plugin)) {
		pr_debug("%s: false as %d is non-root without bind or plugin\n", __func__, mi->mnt_id);
		return false;
	}

shared:
	/* Mount only after all parents of our propagation group mounted */
	if (!list_empty(&mi->mnt_propagate)) {
		struct mount_info *p;

		list_for_each_entry(p, &mi->mnt_propagate, mnt_propagate) {
			BUG_ON(!p->parent);
			if (!p->parent->mounted) {
				pr_debug("%s: false as %d has unmounted parent %d of its propagation group\n", __func__,
					 mi->mnt_id, p->parent->mnt_id);
				return false;
			}
		}
	}

	/*
	 * Mount only after all children of share, which shouldn't
	 * (but can if wrong order) propagate to us, are mounted
	 */
	if (mi->shared_id) {
		struct mount_info *s, *c, *p, *t;
		LIST_HEAD(mi_notprop);
		bool can = true;

		/* Add all children of the shared group */
		list_for_each_entry(s, &mi->mnt_share, mnt_share) {
			list_for_each_entry(c, &s->children, siblings) {
				char root_path[PATH_MAX];
				int ret;

				ret = root_path_from_parent(c, root_path, PATH_MAX);
				BUG_ON(ret);

				/* Mount is out of our root */
				if (!issubpath(root_path, mi->root))
					continue;

				list_add(&c->mnt_notprop, &mi_notprop);
			}
		}

		/* Delete all members of our children's propagation groups */
		list_for_each_entry(c, &mi->children, siblings) {
			list_for_each_entry(p, &c->mnt_propagate, mnt_propagate) {
				list_del_init(&p->mnt_notprop);
			}
		}

		/* Delete all members of our propagation group */
		list_for_each_entry(p, &mi->mnt_propagate, mnt_propagate) {
			list_del_init(&p->mnt_notprop);
		}

		/* Delete self */
		list_del_init(&mi->mnt_notprop);

		/* Check not propagated mounts mounted and cleanup list */
		list_for_each_entry_safe(p, t, &mi_notprop, mnt_notprop) {
			if (!p->mounted) {
				pr_debug("%s: false as %d has unmounted 'anti'-propagation mount %d\n", __func__,
					 mi->mnt_id, p->mnt_id);
				can = false;
			}
			list_del_init(&p->mnt_notprop);
		}

		if (!can)
			return false;
	}

	return true;
}

static int do_mount_root(struct mount_info *mi)
{
	if (restore_shared_options(mi, !mi->shared_id && !mi->master_id, mi->shared_id, mi->master_id))
		return -1;

	return fetch_rt_stat(mi, service_mountpoint(mi));
}

static int do_close_one(struct mount_info *mi)
{
	close_safe(&mi->fd);
	return 0;
}

static int set_unbindable(struct mount_info *mi)
{
	if (mount(NULL, service_mountpoint(mi), NULL, MS_UNBINDABLE, NULL)) {
		pr_perror("Failed setting unbindable flag on %d", mi->mnt_id);
		return -1;
	}

	return 0;
}

static int do_mount_one(struct mount_info *mi)
{
	int ret;

	if (mi->mounted)
		return 0;

	if (!can_mount_now(mi)) {
		pr_debug("Postpone mount %s(%d)\n", mi->ns_mountpoint, mi->mnt_id);
		return 1;
	}

	if ((mi->parent && mi->parent != root_yard_mp) && !strcmp(mi->parent->ns_mountpoint, mi->ns_mountpoint)) {
		mi->parent->fd = open(service_mountpoint(mi->parent), O_PATH);
		if (mi->parent->fd < 0) {
			pr_perror("Unable to open %s", service_mountpoint(mi));
			return -1;
		}
	}

	pr_debug("\tMounting %s %d@%s (%d)\n", mi->fstype->name, mi->mnt_id, service_mountpoint(mi), mi->need_plugin);

	if (rst_mnt_is_root(mi)) {
		int fd;
		unsigned long flags = MS_BIND | MS_REC;

		if (opts.root == NULL) {
			pr_err("The --root option is required to restore a mount namespace\n");
			return -1;
		}

		/* do_mount_root() is called from populate_mnt_ns() */
		if (root_ns_mask & CLONE_NEWUSER) {
			fd = open(service_mountpoint(mi), O_PATH);
			if (fd < 0) {
				pr_perror("Unable to open %s", service_mountpoint(mi));
				return -1;
			}

			if (userns_call(mount_root, 0, &flags, sizeof(flags), fd)) {
				pr_err("Unable to mount %s\n", service_mountpoint(mi));
				close(fd);
				return -1;
			}
			close(fd);
		} else {
			if (mount(opts.root, service_mountpoint(mi), NULL, flags, NULL)) {
				pr_perror("Unable to mount %s %s (id=%d)", opts.root, service_mountpoint(mi),
					  mi->mnt_id);
				return -1;
			}
		}

		if (do_mount_root(mi))
			return -1;
		mi->mounted = true;
		ret = 0;
	} else if (!mi->bind && !mi->need_plugin && !mnt_is_nodev_external(mi)) {
		ret = do_new_mount(mi);
	} else {
		ret = do_bind_mount(mi);
	}

	if (ret == 0 && fetch_rt_stat(mi, service_mountpoint(mi)))
		return -1;

	if (ret == 0 && propagate_mount(mi))
		return -1;

	if (mi->fstype->code == FSTYPE__UNSUPPORTED) {
		struct statfs st;

		if (statfs(service_mountpoint(mi), &st)) {
			pr_perror("Unable to statfs %s", service_mountpoint(mi));
			return -1;
		}
		if (st.f_type == BTRFS_SUPER_MAGIC)
			mi->fstype = find_fstype_by_name("btrfs");
	}

	return ret;
}

static int do_umount_one(struct mount_info *mi)
{
	if (!mi->parent)
		return 0;

	if (mount("none", service_mountpoint(mi->parent), "none", MS_REC | MS_PRIVATE, NULL)) {
		pr_perror("Can't mark %s as private", service_mountpoint(mi->parent));
		return -1;
	}

	if (umount(service_mountpoint(mi))) {
		pr_perror("Can't umount at %s", service_mountpoint(mi));
		return -1;
	}

	pr_info("Umounted at %s\n", service_mountpoint(mi));
	return 0;
}

/*
 * If a mount overmounts other mounts, it is restored separately in the roots
 * yard and then moved to the right place.
 *
 * mnt_remap_entry is created for each such mount and it's added into
 * mnt_remap_list. The origin mount point is replaced on a new one in
 * roots_yard where it will be restored. The remapped mount will be
 * moved to the right places after restoring all mounts.
 */
static LIST_HEAD(mnt_remap_list);
static int remap_id;

struct mnt_remap_entry {
	struct mount_info *mi;	   /* child is remapped into the root yards */
	struct mount_info *parent; /* the origin parent for the child*/
	struct list_head node;
};

static int do_remap_mount(struct mount_info *m)
{
	int len;

	/* A path in root_yard has a fixed size, so it can be replaced. */
	len = print_ns_root(m->nsid, remap_id, m->mountpoint, PATH_MAX);
	m->mountpoint[len] = '/';

	return 0;
}

static int try_remap_mount(struct mount_info *m)
{
	struct mnt_remap_entry *r;

	if (!mnt_needs_remap(m))
		return 0;

	BUG_ON(!m->parent);

	r = xmalloc(sizeof(struct mnt_remap_entry));
	if (!r)
		return -1;

	r->mi = m;
	list_add_tail(&r->node, &mnt_remap_list);

	return 0;
}

static int find_remap_mounts(struct mount_info *root)
{
	struct mnt_remap_entry *r;
	struct mount_info *m;

	/*
	 * It's impossible to change a tree without interrupting
	 * enumeration, so on the first step mounts are added
	 * into mnt_remap_list and then they are connected to root_yard_mp.
	 */
	if (mnt_tree_for_each(root, try_remap_mount))
		return -1;

	/* Move remapped mounts to root_yard */
	list_for_each_entry(r, &mnt_remap_list, node) {
		m = r->mi;
		r->parent = m->parent;
		m->parent = root_yard_mp;
		list_del(&m->siblings);
		list_add(&m->siblings, &root_yard_mp->children);

		remap_id++;
		mnt_tree_for_each(m, do_remap_mount);
		pr_debug("Restore the %d mount in %s\n", m->mnt_id, m->mountpoint);
	}

	return 0;
}

/* Move remapped mounts to places where they have to be */
static int fixup_remap_mounts(void)
{
	struct mnt_remap_entry *r;

	list_for_each_entry(r, &mnt_remap_list, node) {
		struct mount_info *m = r->mi;
		char path[PATH_MAX];
		int len;

		strncpy(path, m->mountpoint, PATH_MAX - 1);
		path[PATH_MAX - 1] = 0;
		len = print_ns_root(m->nsid, 0, path, PATH_MAX);
		path[len] = '/';

		pr_debug("Move mount %s -> %s\n", m->mountpoint, path);
		if (mount(m->mountpoint, path, NULL, MS_MOVE, NULL)) {
			pr_perror("Unable to move mount %s -> %s", m->mountpoint, path);
			return -1;
		}

		/* Insert child back to its place in the tree */
		list_del(&r->mi->siblings);
		list_add(&r->mi->siblings, &r->parent->children);
		r->mi->parent = r->parent;
	}

	return 0;
}

int cr_pivot_root(char *root)
{
	char tmp_dir_tmpl[] = "crtools-put-root.XXXXXX";
	bool tmp_dir = false;
	char *put_root = "tmp";
	int exit_code = -1;
	struct stat st;

	pr_info("Move the root to %s\n", root ?: ".");

	if (root) {
		if (chdir(root)) {
			pr_perror("chdir(%s) failed", root);
			return -1;
		}
	}

	if (stat(put_root, &st) || !S_ISDIR(st.st_mode)) {
		put_root = mkdtemp(tmp_dir_tmpl);
		if (put_root == NULL) {
			pr_perror("Can't create a temporary directory");
			return -1;
		}
		tmp_dir = true;
	}

	if (mount(put_root, put_root, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to mount tmpfs in %s", put_root);
		goto err_root;
	}

	if (mount(NULL, put_root, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", put_root);
		goto err_tmpfs;
	}

	if (pivot_root(".", put_root)) {
		pr_perror("pivot_root(., %s) failed", put_root);
		goto err_tmpfs;
	}

	if (mount("none", put_root, "none", MS_REC | MS_SLAVE, NULL)) {
		pr_perror("Can't remount root with MS_PRIVATE");
		return -1;
	}

	exit_code = 0;

	if (umount2(put_root, MNT_DETACH)) {
		pr_perror("Can't umount %s", put_root);
		return -1;
	}

err_tmpfs:
	if (umount2(put_root, MNT_DETACH)) {
		pr_perror("Can't umount %s", put_root);
		return -1;
	}

err_root:
	if (tmp_dir && rmdir(put_root)) {
		pr_perror("Can't remove the directory %s", put_root);
		return -1;
	}

	return exit_code;
}

struct mount_info *mnt_entry_alloc(bool rst)
{
	struct mount_info *new;

	/*
	 * We rely on xzalloc here for MOUNT_INVALID_DEV.
	 */
	BUILD_BUG_ON(MOUNT_INVALID_DEV);

	new = xzalloc(sizeof(struct mount_info));
	if (new) {
		if (rst) {
			new->rmi = shmalloc(sizeof(struct rst_mount_info));
			if (!new->rmi) {
				xfree(new);
				return NULL;
			}
			memset(new->rmi, 0, sizeof(struct rst_mount_info));
		}
		new->mp_fd_id = -1;
		new->mnt_fd_id = -1;
		new->is_dir = -1;
		new->fd = -1;
		new->is_overmounted = -1;
		INIT_LIST_HEAD(&new->children);
		INIT_LIST_HEAD(&new->siblings);
		INIT_LIST_HEAD(&new->mnt_slave_list);
		INIT_LIST_HEAD(&new->mnt_ext_slave);
		INIT_LIST_HEAD(&new->mnt_share);
		INIT_LIST_HEAD(&new->mnt_bind);
		INIT_LIST_HEAD(&new->mnt_propagate);
		INIT_LIST_HEAD(&new->mnt_notprop);
		INIT_LIST_HEAD(&new->mnt_unbindable);
		INIT_LIST_HEAD(&new->postpone);
		INIT_LIST_HEAD(&new->deleted_list);
	}
	return new;
}

void mnt_entry_free(struct mount_info *mi)
{
	if (mi) {
		xfree(mi->root);
		xfree(mi->mountpoint);
		xfree(mi->plain_mountpoint);
		xfree(mi->source);
		xfree(mi->options);
		xfree(mi->fsname);
		xfree(mi);
	}
}

/*
 * Helper for getting a path to where the namespace's root
 * is re-constructed.
 */
int print_ns_root(struct ns_id *ns, int remap_id, char *buf, int bs)
{
	return snprintf(buf, bs, "%s/%d-%010d", mnt_roots, ns->id, remap_id);
}

static int create_mnt_roots(void)
{
	int exit_code = -1;

	if (mnt_roots)
		return 0;

	mnt_roots = xstrdup("/tmp/.criu.mntns.XXXXXX");
	if (mnt_roots == NULL)
		goto out;

	if (mkdtemp(mnt_roots) == NULL) {
		pr_perror("Unable to create a temporary directory");
		mnt_roots = NULL;
		goto out;
	}
	chmod(mnt_roots, 0777);

	exit_code = 0;
out:
	return exit_code;
}

static int get_mp_root(MntEntry *me, struct mount_info *mi)
{
	char *ext = NULL;

	BUG_ON(me->ext_mount && me->ext_key);

	/* Forward compatibility fixup */
	if (me->ext_mount) {
		me->ext_key = me->root;
		/*
		 * Putting the id of external mount which is provided by user,
		 * to ->root can confuse mnt_is_external_bind and other functions
		 * which expect to see the path in the file system to the root
		 * of these mount (mounts_equal, mnt_build_ids_tree,
		 * find_fsroot_mount_for, find_best_external_match, etc.)
		 */
		me->root = NO_ROOT_MOUNT;
	}

	mi->root = xstrdup(me->root);
	if (!mi->root)
		return -1;

	if (!me->ext_key)
		goto out;

	/*
	 * External mount point -- get the reverse mapping
	 * from the command line and put into root's place
	 */

	if (!strcmp(me->ext_key, AUTODETECTED_MOUNT)) {
		if (!opts.autodetect_ext_mounts) {
			pr_err("Mount %d:%s is autodetected external mount. "
			       "Try \"--ext-mount-map auto\" to allow them.\n",
			       mi->mnt_id, mi->ns_mountpoint);
			return -1;
		}

		/*
		 * Make up an external mount entry for this
		 * mount point, since we couldn't find a user
		 * supplied one.
		 *
		 * The 'val' was put into mi->source during
		 * dump by resolve_external_mounts().
		 */

		ext = mi->source;
	} else if (!strcmp(me->ext_key, EXTERNAL_DEV_MOUNT)) {
		ext = EXTERNAL_DEV_MOUNT;
	} else {
		ext = ext_mount_lookup(me->ext_key);
		if (!ext) {
			pr_err("No mapping for %d:%s mountpoint\n", mi->mnt_id, mi->ns_mountpoint);
			return -1;
		}
	}

	mi->external = ext;
out:
	pr_debug("\t\tWill mount %d from %s%s\n", mi->mnt_id, ext ?: mi->root, ext ? " (E)" : "");
	return 0;
}

static int get_mp_mountpoint(char *mountpoint, struct mount_info *mi, char *root, int root_len)
{
	int len;

	len = strlen(mountpoint) + root_len + 1;
	mi->mountpoint = xmalloc(len);
	if (!mi->mountpoint)
		return -1;

	/*
	 * For bind-mounts we would also fix the root here
	 * too, but bind-mounts restore merges mountpoint
	 * and root paths together, so there's no need in
	 * that.
	 */

	strcpy(mi->mountpoint, root);
	strcpy(mi->mountpoint + root_len, mountpoint);

	mi->ns_mountpoint = mi->mountpoint + root_len;

	mi->plain_mountpoint = get_plain_mountpoint(mi->mnt_id, NULL);
	if (!mi->plain_mountpoint)
		return -1;

	pr_debug("\t\tWill mount %d @ %s %s\n", mi->mnt_id, service_mountpoint(mi), mi->ns_mountpoint);
	return 0;
}

static char *mount_update_lsm_context(char *mount_opts)
{
	cleanup_free char *before_context = NULL;
	char *other_options;
	char *context_start;
	char *context_end;
	char *old_context;
	char *new_options;
	int ret;

	old_context = strstr(mount_opts, CONTEXT_OPT);

	if (!old_context || !opts.lsm_mount_context)
		return xstrdup(mount_opts);

	/*
	 * If the user specified a different mount_context we need
	 * to replace the existing mount context in the mount
	 * options with the one specified by the user.
	 *
	 * The original mount options will be something like:
	 *
	 *  context="system_u:object_r:container_file_t:s0:c82,c137",inode64
	 *
	 * and it needs to be replaced with opts.lsm_mount_context.
	 *
	 * The content between 'context=' and ',inode64' will be replaced
	 * with opts.lsm_mount_context in quotes.
	 */

	/* Skip 'context=' */
	context_start = old_context + strlen(CONTEXT_OPT);
	if (context_start[0] == '"' && context_start + 1 < mount_opts + strlen(mount_opts)) {
		/* Skip quotes */
		context_end = strchr(context_start + 1, '"');
		if (!context_end) {
			pr_err("Failed parsing mount option 'context'\n");
			return NULL;
		}
	} else {
		context_end = context_start;
	}

	/* Find next after optionally skipping quotes. */
	other_options = strchr(context_end, ',');

	before_context = xstrdup(mount_opts);
	if (unlikely(!before_context))
		return NULL;
	before_context[context_start - mount_opts] = 0;

	ret = asprintf(&new_options, "%s\"%s\"%s", before_context, opts.lsm_mount_context,
		       other_options ? other_options : "");
	if (unlikely(ret < 0))
		return NULL;
	pr_debug("\t\tChanged mount 'context=' to %s\n", new_options);

	return new_options;
}

static int collect_mnt_from_image(struct mount_info **head, struct mount_info **tail, struct ns_id *nsid)
{
	MntEntry *me = NULL;
	int ret, root_len = 1;
	struct cr_img *img;
	char root[PATH_MAX] = ".";

	img = open_image(CR_FD_MNTS, O_RSTR, nsid->id);
	if (!img)
		return -1;

	root_len = print_ns_root(nsid, 0, root, sizeof(root));

	pr_debug("Reading mountpoint images (id %d pid %d)\n", nsid->id, (int)nsid->ns_pid);

	while (1) {
		struct mount_info *pm;

		ret = pb_read_one_eof(img, &me, PB_MNT);
		if (ret <= 0)
			break;

		pm = mnt_entry_alloc(true);
		if (!pm)
			goto err;

		pm->nsid = nsid;
		mntinfo_add_list_before(head, pm);
		if (!*tail)
			*tail = pm;

		pm->mnt_id = me->mnt_id;
		pm->parent_mnt_id = me->parent_mnt_id;
		pm->s_dev = me->root_dev;
		pm->flags = me->flags;
		pm->sb_flags = me->sb_flags;
		if (!me->has_sb_flags) {
			const unsigned int mflags = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE | MS_NOSUID |
						    MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME | MS_RELATIME;

			/*
			 * In old images mnt and sb flags are saved together.
			 * Here we separate them and save the old logic about MS_RDONLY.
			 */

			pm->sb_flags = pm->flags & ~mflags;
			pm->flags = pm->flags & mflags;
		}
		pm->shared_id = me->shared_id;
		pm->master_id = me->master_id;
		pm->need_plugin = me->with_plugin;
		pm->deleted = me->deleted;
		pm->is_ns_root = is_root(me->mountpoint);
		if (me->has_internal_sharing)
			pm->internal_sharing = me->internal_sharing;

		pm->source = xstrdup(me->source);
		if (!pm->source)
			goto err;

		pm->options = mount_update_lsm_context(me->options);
		if (unlikely(!pm->options))
			goto err;

		if (me->fstype != FSTYPE__AUTO && me->fsname) {
			pr_err("fsname can be set only for FSTYPE__AUTO mounts\n");
			goto err;
		}

		/* FIXME: abort unsupported early */
		pm->fstype = decode_fstype(me->fstype);
		if (pm->fstype->collect && (pm->fstype->collect(pm) < 0))
			goto err;

		if (me->fsname) {
			pm->fsname = xstrdup(me->fsname);
			if (!pm->fsname)
				goto err;
		}

		if (get_mp_root(me, pm))
			goto err;

		if (get_mp_mountpoint(me->mountpoint, pm, root, root_len))
			goto err;

		pr_debug("\t"
			 "Read %d mp @ %s\n",
			 pm->mnt_id, pm->ns_mountpoint);
	}

	if (me)
		mnt_entry__free_unpacked(me, NULL);

	close_image(img);

	return 0;
err:
	close_image(img);
	return -1;
}

static int merge_mount_trees(void)
{
	struct ns_id *nsid;

	root_yard_mp = mnt_entry_alloc(true);
	if (!root_yard_mp)
		return -1;

	root_yard_mp->mountpoint = mnt_roots;
	root_yard_mp->plain_mountpoint = xstrdup(mnt_roots);
	if (!root_yard_mp->plain_mountpoint)
		return -1;
	root_yard_mp->is_dir = true;
	root_yard_mp->mounted = true;
	root_yard_mp->mnt_bind_is_populated = true;
	root_yard_mp->is_overmounted = false;
	root_yard_mp->mnt_id = HELPER_MNT_ID;

	/* Merge mount trees together under root_yard_mp */
	for (nsid = ns_ids; nsid; nsid = nsid->next) {
		struct mount_info *root;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		root = nsid->mnt.mntinfo_tree;

		pr_debug("Mountpoint %d (@%s) moved to the root yard\n", root->mnt_id, root->ns_mountpoint);
		root->parent = root_yard_mp;
		list_add(&root->siblings, &root_yard_mp->children);
	}

	return 0;
}

int read_mnt_ns_img(void)
{
	struct mount_info *pms = NULL;
	struct ns_id *nsid;

	if (!(root_ns_mask & CLONE_NEWNS)) {
		mntinfo = NULL;
		return 0;
	}

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		struct mount_info *head = NULL, *tail = NULL;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (collect_mnt_from_image(&head, &tail, nsid))
			return -1;

		nsid->mnt.mntinfo_tree = mnt_build_tree(head);
		if (!nsid->mnt.mntinfo_tree)
			return -1;

		/* mntns root mounts are always directories */
		nsid->mnt.mntinfo_tree->is_dir = true;

		tail->next = pms;
		pms = head;
	}

	mntinfo = pms;

	search_bindmounts();
	prepare_is_overmounted();

	if (!opts.mntns_compat_mode && resolve_shared_mounts_v2())
		return -1;

	if (merge_mount_trees())
		return -1;

	return 0;
}

int rst_get_mnt_root(int mnt_id, char *path, int plen)
{
	struct mount_info *m;

	if (!(root_ns_mask & CLONE_NEWNS) || mnt_id == -1)
		goto rroot;

	m = lookup_mnt_id(mnt_id);
	if (m == NULL)
		return -1;

	return print_ns_root(m->nsid, 0, path, plen);

rroot:
	path[0] = '/';
	path[1] = '\0';
	return 1;
}

int mntns_maybe_create_roots(void)
{
	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	return create_mnt_roots();
}

static int do_restore_task_mnt_ns(struct ns_id *nsid)
{
	int fd;

	fd = fdstore_get(nsid->mnt.nsfd_id);
	if (fd < 0)
		return -1;

	if (setns(fd, CLONE_NEWNS)) {
		pr_perror("Can't restore mntns");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int restore_task_mnt_ns(struct pstree_item *current)
{
	if ((root_ns_mask & CLONE_NEWNS) == 0)
		return 0;

	if (current->ids && current->ids->has_mnt_ns_id) {
		struct pstree_item *parent = current->parent;
		unsigned int id = current->ids->mnt_ns_id;
		struct ns_id *nsid;

		/* Zombies and helpers can have ids == 0 so we skip them */
		while (parent && !parent->ids)
			parent = parent->parent;

		/**
		 * Our parent had restored the mount namespace before forking
		 * us and if we have the same mntns we just stay there.
		 */
		if (parent && id == parent->ids->mnt_ns_id)
			return 0;

		nsid = lookup_ns_by_id(id, &mnt_ns_desc);
		if (nsid == NULL) {
			pr_err("Can't find mount namespace %d\n", id);
			return -1;
		}

		BUG_ON(nsid->type == NS_CRIU);

		if (do_restore_task_mnt_ns(nsid))
			return -1;
	}

	return 0;
}

void fini_restore_mntns(void)
{
	struct ns_id *nsid;

	if (!(root_ns_mask & CLONE_NEWNS))
		return;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;
		nsid->ns_populated = true;
	}
}

/*
 * All nested mount namespaces are restore as sub-trees of the root namespace.
 */
static int populate_roots_yard(struct mount_info *cr_time)
{
	struct mnt_remap_entry *r;
	char path[PATH_MAX];
	struct ns_id *nsid;

	if (make_yard(mnt_roots))
		return -1;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		print_ns_root(nsid, 0, path, sizeof(path));
		if (mkdir(path, 0600)) {
			pr_perror("Unable to create %s", path);
			return -1;
		}
	}

	/*
	 * mnt_remap_list is filled in find_remap_mounts() and
	 * contains mounts which has to be restored separately
	 */
	list_for_each_entry(r, &mnt_remap_list, node) {
		if (mkdirpat(AT_FDCWD, service_mountpoint(r->mi), 0755)) {
			pr_perror("Unable to create %s", service_mountpoint(r->mi));
			return -1;
		}
	}

	if (cr_time && mkdirpat(AT_FDCWD, service_mountpoint(cr_time), 0755)) {
		pr_perror("Unable to create %s", service_mountpoint(cr_time));
		return -1;
	}

	return 0;
}

static int populate_mnt_ns(void)
{
	struct mount_info *cr_time = NULL;
	int ret;

#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
	if (!opts.has_binfmt_misc && !list_empty(&binfmt_misc_list)) {
		/* Add to mount tree. Generic code will mount it later */
		cr_time = add_cr_time_mount(root_yard_mp, "binfmt_misc", "binfmt_misc", 0, true);
		if (!cr_time)
			return -1;
	}
#endif

	if (resolve_shared_mounts(mntinfo))
		return -1;

	if (validate_mounts(mntinfo, false))
		return -1;

	if (find_remap_mounts(root_yard_mp))
		return -1;

	if (populate_roots_yard(cr_time))
		return -1;

	if (mount_clean_path())
		return -1;

	ret = mnt_tree_for_each(root_yard_mp, do_mount_one);
	mnt_tree_for_each(root_yard_mp, do_close_one);

	if (ret == 0) {
		struct mount_info *mi;

		/*
		 * Mounts in delayed_unbindable list were temporary mounted as
		 * private instead of unbindable so that do_mount_one can bind
		 * from them, now we are ready to fix it.
		 */
		list_for_each_entry(mi, &delayed_unbindable, mnt_unbindable)
			if (set_unbindable(mi))
				return -1;
	}

	if (ret == 0 && fixup_remap_mounts())
		return -1;

	if (umount_clean_path())
		return -1;
	return ret;
}

static int __depopulate_roots_yard(void)
{
	int ret = 0;

	if (mnt_roots == NULL)
		return 0;

	if (mount("none", mnt_roots, "none", MS_REC | MS_PRIVATE, NULL)) {
		pr_perror("Can't remount root with MS_PRIVATE");
		ret = 1;
	}
	/*
	 * Don't exit after a first error, because this function
	 * can be used to rollback in a error case.
	 * Don't worry about MNT_DETACH, because files are restored after this
	 * and nobody will not be restored from a wrong mount namespace.
	 */
	if (umount2(mnt_roots, MNT_DETACH)) {
		pr_perror("Can't unmount %s", mnt_roots);
		ret = -1;
	}

	if (rmdir(mnt_roots)) {
		pr_perror("Can't remove the directory %s", mnt_roots);
		ret = -1;
	}

	return ret;
}

int depopulate_roots_yard(int mntns_fd, bool only_ghosts)
{
	int ret = 0, old_cwd = -1, old_ns = -1;

	if (mntns_fd < 0) {
		ret |= try_clean_remaps(only_ghosts);
		cleanup_mnt_ns();
		return ret;
	}

	pr_info("Switching to new ns to clean ghosts\n");

	old_cwd = open(".", O_PATH);
	if (old_cwd < 0) {
		pr_perror("Unable to open cwd");
		return -1;
	}

	old_ns = open_proc(PROC_SELF, "ns/mnt");
	if (old_ns < 0) {
		pr_perror("`- Can't keep old ns");
		close(old_cwd);
		return -1;
	}
	if (setns(mntns_fd, CLONE_NEWNS) < 0) {
		pr_perror("`- Can't switch");
		close(old_ns);
		close(old_cwd);
		return -1;
	}

	if (try_clean_remaps(only_ghosts))
		ret = -1;

	if (__depopulate_roots_yard())
		ret = -1;

	if (setns(old_ns, CLONE_NEWNS) < 0) {
		pr_perror("Fail to switch back!");
		ret = -1;
	}
	close(old_ns);

	if (fchdir(old_cwd)) {
		pr_perror("Unable to restore cwd");
		ret = -1;
	}
	close(old_cwd);

	return ret;
}

void cleanup_mnt_ns(void)
{
	if (mnt_roots == NULL)
		return;

	if (rmdir(mnt_roots))
		pr_perror("Can't remove the directory %s", mnt_roots);
}

int prepare_mnt_ns(void)
{
	int ret = -1, rst = -1, fd;
	struct ns_id ns = { .type = NS_CRIU, .ns_pid = PROC_SELF, .nd = &mnt_ns_desc };
	struct ns_id *nsid;

	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	pr_info("Restoring mount namespace\n");

	if (!opts.root) {
		struct mount_info *old;

		if (chdir("/")) {
			pr_perror("chdir(\"/\") failed");
			return -1;
		}

		old = collect_mntinfo(&ns, false);
		if (old == NULL)
			return -1;
		/*
		 * The new mount namespace is filled with the mountpoint
		 * clones from the original one. We have to umount them
		 * prior to recreating new ones.
		 */
		pr_info("Cleaning mount namespace\n");
		if (mnt_tree_for_each_reverse(ns.mnt.mntinfo_tree, do_umount_one)) {
			free_mntinfo(old);
			return -1;
		}

		free_mntinfo(old);
	}

	if (!opts.mntns_compat_mode)
		return prepare_mnt_ns_v2();

	ret = populate_mnt_ns();
	if (ret)
		return -1;

	rst = open_proc(PROC_SELF, "ns/mnt");
	if (rst < 0)
		return -1;

	/* restore non-root namespaces */
	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		char path[PATH_MAX];

		if (nsid->nd != &mnt_ns_desc)
			continue;
		/* Create the new mount namespace */
		if (unshare(CLONE_NEWNS)) {
			pr_perror("Unable to create a new mntns");
			goto err;
		}

		fd = open_proc(PROC_SELF, "ns/mnt");
		if (fd < 0)
			goto err;

		if (nsid->type == NS_ROOT) {
			/*
			 * We need to create a mount namespace which will be
			 * used to clean up remap files
			 * (depopulate_roots_yard).  The namespace where mounts
			 * was restored has to be restored as a root mount
			 * namespace, because there are file descriptors
			 * linked with it (e.g. to bind-mount slave pty-s).
			 */
			if (setns(rst, CLONE_NEWNS)) {
				pr_perror("Can't restore mntns back");
				goto err;
			}
			SWAP(rst, fd);
		}

		/* Pin one with a file descriptor */
		nsid->mnt.nsfd_id = fdstore_add(fd);
		close(fd);
		if (nsid->mnt.nsfd_id < 0) {
			pr_err("Can't add ns fd\n");
			goto err;
		}

		/* Set its root */
		print_ns_root(nsid, 0, path, sizeof(path) - 1);
		if (cr_pivot_root(path))
			goto err;

		/* root fd is used to restore file mappings */
		fd = open_proc(PROC_SELF, "root");
		if (fd < 0)
			goto err;
		nsid->mnt.root_fd_id = fdstore_add(fd);
		if (nsid->mnt.root_fd_id < 0) {
			pr_err("Can't add root fd\n");
			close(fd);
			goto err;
		}
		close(fd);

		/* And return back to regain the access to the roots yard */
		if (setns(rst, CLONE_NEWNS)) {
			pr_perror("Can't restore mntns back");
			goto err;
		}
	}
	close(rst);

	return ret;
err:
	if (rst >= 0)
		/* coverity[check_return] */
		restore_ns(rst, &mnt_ns_desc);
	return -1;
}

static int mntns_root_pid = -1;
static int mntns_set_root_fd(pid_t pid, int fd)
{
	int ret;

	ret = install_service_fd(ROOT_FD_OFF, fd);
	if (ret >= 0)
		mntns_root_pid = pid;

	return ret;
}

int __mntns_get_root_fd(pid_t pid)
{
	int fd, pfd;
	int ret;
	char path[PATH_MAX + 1];

	if (mntns_root_pid == pid) /* The required root is already opened */
		return get_service_fd(ROOT_FD_OFF);

	if (!(root_ns_mask & CLONE_NEWNS)) {
		/*
		 * If criu and tasks we dump live in the same mount
		 * namespace, we can just open the root directory.
		 * All paths resolution would occur relative to criu's
		 * root. Even if it is not namespace's root, provided
		 * file paths are resolved, we'd get consistent dump.
		 */
		fd = open("/", O_RDONLY | O_DIRECTORY);
		if (fd < 0) {
			pr_perror("Can't open root");
			return -1;
		}

		goto set_root;
	}

	/*
	 * If /proc/pid/root links on '/', it signs that a root of the task
	 * and a root of mntns is the same.
	 */

	pfd = open_pid_proc(pid);
	ret = readlinkat(pfd, "root", path, sizeof(path) - 1);
	if (ret < 0) {
		close_pid_proc();
		return ret;
	}

	path[ret] = '\0';

	if (ret != 1 || path[0] != '/') {
		pr_err("The root task has another root than mntns: %s\n", path);
		close_pid_proc();
		return -1;
	}

	fd = openat(pfd, "root", O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0) {
		pr_perror("Can't open the task root");
		return -1;
	}

set_root:
	return mntns_set_root_fd(pid, fd);
}

int mntns_get_root_fd(struct ns_id *mntns)
{
	if (!(root_ns_mask & CLONE_NEWNS))
		return __mntns_get_root_fd(0);

	if (!mntns)
		return -1;

	/*
	 * All namespaces are restored from the root task and during the
	 * CR_STATE_FORKING stage the root task has two file descriptors for
	 * each mntns. One is associated with a namespace and another one is a
	 * root of this mntns.
	 *
	 * When a non-root task is forked, it enters into a proper mount
	 * namespace, restores private mappings and forks children. Some of
	 * these mappings can be associated with files from other namespaces.
	 *
	 * After the CR_STATE_FORKING stage the root task has to close all
	 * mntns file descriptors to restore its descriptors and at this moment
	 * we know that all tasks live in their mount namespaces.
	 *
	 * If we find that a mount namespace isn't populated, we can get its
	 * root from the root task.
	 */

	if (!mntns->ns_populated) {
		int fd;

		fd = fdstore_get(mntns->mnt.root_fd_id);
		if (fd < 0)
			return -1;

		return mntns_set_root_fd(mntns->ns_pid, fd);
	}

	return __mntns_get_root_fd(mntns->ns_pid);
}

struct ns_id *lookup_nsid_by_mnt_id(int mnt_id)
{
	struct mount_info *mi;

	/*
	 * Kernel before 3.15 doesn't show mnt_id for file descriptors.
	 * mnt_id isn't saved for files, if mntns isn't dumped.
	 * In both these cases we have only one root, so here
	 * is not matter which mount will be restored.
	 */
	if (mnt_id == -1)
		mi = mntinfo;
	else
		mi = lookup_mnt_id(mnt_id);
	return mi ? mi->nsid : NULL;
}

int mntns_get_root_by_mnt_id(int mnt_id)
{
	struct ns_id *mntns = NULL;

	if (root_ns_mask & CLONE_NEWNS) {
		mntns = lookup_nsid_by_mnt_id(mnt_id);
		BUG_ON(mntns == NULL);
	}

	return mntns_get_root_fd(mntns);
}

struct collect_mntns_arg {
	bool need_to_validate;
	bool for_dump;
};

static int collect_mntns(struct ns_id *ns, void *__arg)
{
	struct collect_mntns_arg *arg = __arg;
	struct mount_info *pms;

	pms = collect_mntinfo(ns, arg->for_dump);
	if (!pms)
		return -1;

	if (arg->for_dump && ns->type != NS_CRIU)
		arg->need_to_validate = true;

	mntinfo_add_list(pms);

	return 0;
}

int collect_mnt_namespaces(bool for_dump)
{
	struct collect_mntns_arg arg;
	int ret;

	arg.for_dump = for_dump;
	arg.need_to_validate = false;

	ret = walk_namespaces(&mnt_ns_desc, collect_mntns, &arg);
	if (ret)
		goto err;

	search_bindmounts();

#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
	if (for_dump && !opts.has_binfmt_misc) {
		unsigned int s_dev = 0;
		struct ns_id *ns;

		for (ns = ns_ids; ns != NULL; ns = ns->next) {
			if (ns->type == NS_ROOT && ns->nd == &mnt_ns_desc)
				break;
		}

		if (ns) {
			ret = mount_cr_time_mount(ns, &s_dev, "binfmt_misc", "/" BINFMT_MISC_HOME, "binfmt_misc");
			if (ret == -1) {
				goto err;
			} else if (ret == 0 && !add_cr_time_mount(ns->mnt.mntinfo_tree, "binfmt_misc", BINFMT_MISC_HOME,
								  s_dev, false)) {
				ret = -1;
				goto err;
			}
		}
	}
#endif

	ret = resolve_external_mounts(mntinfo);
	if (ret)
		goto err;

	if (arg.need_to_validate) {
		ret = -1;

		if (resolve_shared_mounts(mntinfo))
			goto err;
		if (validate_mounts(mntinfo, true))
			goto err;
	}

	ret = 0;
err:
	return ret;
}

int dump_mnt_namespaces(void)
{
	struct ns_id *nsid;

	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc || nsid->type == NS_CRIU)
			continue;

		if ((nsid->type == NS_OTHER) && check_mnt_id()) {
			pr_err("Nested mount namespaces are not supported "
			       "without mnt_id in fdinfo\n");
			return -1;
		}

		if (dump_mnt_ns(nsid, nsid->mnt.mntinfo_list))
			return -1;
	}

	return 0;
}

void clean_cr_time_mounts(void)
{
	struct mount_info *mi;
	int ns_old, ret;

	for (mi = mntinfo; mi; mi = mi->next) {
		int cwd_fd;

		if (mi->mnt_id != HELPER_MNT_ID)
			continue;
		ret = switch_mnt_ns(mi->nsid->ns_pid, &ns_old, &cwd_fd);
		if (ret) {
			pr_err("Can't switch to pid's %u mnt_ns\n", mi->nsid->ns_pid);
			continue;
		}

		if (umount(mi->ns_mountpoint) < 0)
			pr_perror("Can't umount forced mount %s", mi->ns_mountpoint);

		if (restore_mnt_ns(ns_old, &cwd_fd)) {
			pr_err("cleanup_forced_mounts exiting with wrong mnt_ns\n");
			return;
		}
	}
}

struct ns_desc mnt_ns_desc = NS_DESC_ENTRY(CLONE_NEWNS, "mnt");

static int call_helper_process(int (*call)(void *), void *arg)
{
	int pid, status, exit_code = -1;

	/*
	 * Running new helper process on the restore must be
	 * done under last_pid mutex: other tasks may be restoring
	 * threads and the PID we need there might be occupied by
	 * this clone() call.
	 */
	lock_last_pid();

	pid = clone_noasan(call, CLONE_VFORK | CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM, arg);
	if (pid == -1) {
		pr_perror("Can't clone helper process");
		goto out;
	}

	errno = 0;
	if (waitpid(pid, &status, __WALL) != pid) {
		pr_perror("Unable to wait %d", pid);
		goto out;
	}

	if (status) {
		pr_err("Bad child exit status: %d\n", status);
		goto out;
	}

	exit_code = 0;
out:
	unlock_last_pid();
	return exit_code;
}

static int ns_remount_writable(void *arg)
{
	struct mount_info *mi = (struct mount_info *)arg;
	struct ns_id *ns = mi->nsid;

	if (do_restore_task_mnt_ns(ns))
		return 1;
	pr_debug("Switched to mntns %u:%u\n", ns->id, ns->kid);

	if (mount(NULL, mi->ns_mountpoint, NULL, MS_REMOUNT | MS_BIND | (mi->flags & ~(MS_PROPAGATE | MS_RDONLY)),
		  NULL) == -1) {
		pr_perror("Failed to remount %d:%s writable", mi->mnt_id, mi->ns_mountpoint);
		return 1;
	}
	return 0;
}

int try_remount_writable(struct mount_info *mi, bool ns)
{
	int remounted = REMOUNTED_RW;

	/* Don't remount if we are in host mntns to be on the safe side */
	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	if (!ns)
		remounted = REMOUNTED_RW_SERVICE;

	/* All mounts in mntinfo list should have it on restore */
	BUG_ON(mi->rmi == NULL);

	if (mi->flags & MS_RDONLY && !(mi->rmi->remounted_rw & remounted)) {
		if (mnt_is_overmounted(mi)) {
			pr_err("The mount %d is overmounted so paths are invisible\n", mi->mnt_id);
			return -1;
		}

		/* There should be no ghost files on mounts with ro sb */
		if (mi->sb_flags & MS_RDONLY) {
			pr_err("The mount %d has readonly sb\n", mi->mnt_id);
			return -1;
		}

		pr_info("Remount %d:%s writable\n", mi->mnt_id, service_mountpoint(mi));
		if (!ns) {
			if (mount(NULL, service_mountpoint(mi), NULL,
				  MS_REMOUNT | MS_BIND | (mi->flags & ~(MS_PROPAGATE | MS_RDONLY)), NULL) == -1) {
				pr_perror("Failed to remount %d:%s writable", mi->mnt_id, service_mountpoint(mi));
				return -1;
			}
		} else {
			if (call_helper_process(ns_remount_writable, mi))
				return -1;
		}
		mi->rmi->remounted_rw |= remounted;
	}

	return 0;
}

static int __remount_readonly_mounts(struct ns_id *ns)
{
	struct mount_info *mi;
	bool mntns_set = false;

	for (mi = mntinfo; mi; mi = mi->next) {
		if (ns && mi->nsid != ns)
			continue;

		if (!(mi->rmi->remounted_rw & REMOUNTED_RW))
			continue;

		/*
		 * Lets enter the mount namespace lazily, only if we've found the
		 * mount which should be remounted readonly. These saves us
		 * from entering mntns if we have no mounts to remount in it.
		 */
		if (ns && !mntns_set) {
			if (do_restore_task_mnt_ns(ns))
				return -1;
			mntns_set = true;
			pr_debug("Switched to mntns %u:%u\n", ns->id, ns->kid);
		}

		pr_info("Remount %d:%s back to readonly\n", mi->mnt_id, mi->ns_mountpoint);
		if (mount(NULL, mi->ns_mountpoint, NULL, MS_REMOUNT | MS_BIND | (mi->flags & ~MS_PROPAGATE), NULL)) {
			pr_perror("Failed to restore %d:%s mount flags %x", mi->mnt_id, mi->ns_mountpoint, mi->flags);
			return -1;
		}
	}

	return 0;
}

static int ns_remount_readonly_mounts(void *arg)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (__remount_readonly_mounts(nsid))
			return 1;
	}

	return 0;
}

int remount_readonly_mounts(void)
{
	/*
	 * Need a helper process because the root task can share fs via
	 * CLONE_FS and we would not be able to enter mount namespaces
	 */
	return call_helper_process(ns_remount_readonly_mounts, NULL);
}

static struct mount_info *mnt_subtree_next(struct mount_info *mi, struct mount_info *root)
{
	if (!list_empty(&mi->children))
		return list_entry(mi->children.next, struct mount_info, siblings);

	while (mi->parent && mi != root) {
		if (mi->siblings.next == &mi->parent->children)
			mi = mi->parent;
		else
			return list_entry(mi->siblings.next, struct mount_info, siblings);
	}

	return NULL;
}
