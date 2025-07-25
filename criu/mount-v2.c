#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sched.h>

#include "kerndat.h"
#include "log.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "util.h"
#include "filesystems.h"
#include "mount.h"
#include "mount-v2.h"
#include "namespaces.h"
#include "fs-magic.h"
#include "path.h"
#include "files-reg.h"
#include "fdstore.h"
#include "common/list.h"
#include "common/bug.h"
#include "common/compiler.h"

#include "images/mnt.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "mnt-v2: "

LIST_HEAD(sharing_groups);

int check_mount_v2(void)
{
	if (!kdat.has_move_mount_set_group) {
		pr_debug("Mounts-v2 requires MOVE_MOUNT_SET_GROUP support\n");
		return -1;
	}

	if (!kdat.has_openat2) {
		pr_debug("Mounts-v2 requires openat2 support\n");
		return -1;
	}

	return 0;
}

static struct sharing_group *get_sharing_group(int shared_id, int master_id)
{
	struct sharing_group *sg;

	list_for_each_entry(sg, &sharing_groups, list) {
		if (sg->shared_id == shared_id && sg->master_id == master_id)
			return sg;
	}

	return NULL;
}

static struct sharing_group *alloc_sharing_group(int shared_id, int master_id)
{
	struct sharing_group *sg;

	sg = xzalloc(sizeof(struct sharing_group));
	if (!sg)
		return NULL;

	sg->shared_id = shared_id;
	sg->master_id = master_id;

	INIT_LIST_HEAD(&sg->list);
	INIT_LIST_HEAD(&sg->mnt_list);
	INIT_LIST_HEAD(&sg->children);
	INIT_LIST_HEAD(&sg->siblings);

	list_add(&sg->list, &sharing_groups);

	return sg;
}

int resolve_shared_mounts_v2(void)
{
	struct sharing_group *sg;
	struct mount_info *mi;

	/*
	 * Create sharing groups for each unique shared_id+master_id pair and
	 * link each mount to the corresponding sharing group.
	 */
	for (mi = mntinfo; mi; mi = mi->next) {
		if (!mi->shared_id && !mi->master_id)
			continue;

		pr_debug("Inspecting sharing on %2d shared_id %d master_id %d (@%s)\n", mi->mnt_id, mi->shared_id,
			 mi->master_id, mi->ns_mountpoint);

		sg = get_sharing_group(mi->shared_id, mi->master_id);
		if (!sg) {
			sg = alloc_sharing_group(mi->shared_id, mi->master_id);
			if (!sg)
				return -1;
		}

		list_add(&mi->mnt_sharing, &sg->mnt_list);
		mi->sg = sg;
	}

	/*
	 * Collect sharing groups tree. Mount propagation between sharing
	 * groups only goes down this tree, meaning that only mounts of same or
	 * descendant sharing groups receive mount propagation.
	 */
	list_for_each_entry(sg, &sharing_groups, list) {
		if (sg->master_id) {
			struct sharing_group *p;

			/*
			 * Lookup parent sharing group. If one sharing group
			 * has master_id equal to shared_id of another sharing
			 * group than the former is a child (slave) of the
			 * latter. Also sharing groups should not have two
			 * parents so we check this here too.
			 */
			list_for_each_entry(p, &sharing_groups, list) {
				if (p->shared_id != sg->master_id)
					continue;

				if (sg->parent) {
					pr_err("Sharing group (%d, %d) parent collision (%d, %d) (%d, %d)\n",
					       sg->shared_id, sg->master_id, p->shared_id, p->master_id,
					       sg->parent->shared_id, sg->parent->master_id);
					return -1;
				}
				sg->parent = p;

				if (!list_empty(&sg->siblings)) {
					pr_err("External slavery sharing group (%d, %d) has parent (%d, %d)\n",
					       sg->shared_id, sg->master_id, p->shared_id, p->master_id);
					return -1;
				}
				list_add(&sg->siblings, &p->children);
				/* Don't break to check for parent collision */
			}

			/*
			 * If sharing group has master_id but we did't find
			 * parent for it inside the dumped container yet, this
			 * means that the master_id is external and a mount on
			 * host should exist with corresponding shared_id.
			 */
			if (!sg->parent && list_empty(&sg->siblings)) {
				struct mount_info *ext;
				struct sharing_group *s;
				char *source = NULL;

				/*
				 * Though we don't have parent sharing group
				 * (inaccessible sharing), we can still have
				 * siblings, sharing groups with same master_id
				 * but different shared_id, let's collect them
				 * to the list.
				 */
				list_for_each_entry(s, &sharing_groups, list) {
					if (s->master_id != sg->master_id)
						continue;

					if (s->parent) {
						pr_err("External slavery sharing group (%d, %d) has parent (%d, %d)\n",
						       sg->shared_id, sg->master_id, s->parent->shared_id,
						       s->parent->master_id);
						return -1;
					}

					if (!list_empty(&s->siblings)) {
						pr_err("External slavery sharing group collision (%d, %d) (%d, %d)\n",
						       sg->shared_id, sg->master_id, s->shared_id, s->master_id);
						return -1;
					}
					list_add(&s->siblings, &sg->siblings);
				}

				BUG_ON(list_empty(&sg->mnt_list));
				mi = list_entry(sg->mnt_list.next, struct mount_info, mnt_sharing);

				/*
				 * We need to know from which mount on host we
				 * can get this external master_id. There are
				 * two options: mountpoint external mount or
				 * root mount of container.
				 */
				if ((ext = mnt_get_external_bind_nodev(mi)))
					source = ext->external;
				else if (mnt_is_root_bind(mi))
					source = opts.root;

				if (!source) {
					pr_err("Sharing group (%d, %d) "
					       "has unreachable sharing. Try --enable-external-masters.\n",
					       sg->shared_id, sg->master_id);
					return -1;
				}

				sg->source = source;
				list_for_each_entry(s, &sg->siblings, siblings)
					s->source = sg->source;

				pr_debug("Detected external slavery for shared group (%d, %d) with source %s\n",
					 sg->shared_id, sg->master_id, source);
			}
		}
	}

	return 0;
}

/*
 * When first mount from superblock is mounted, give other mounts
 * a hint that they can now just bindmount from the first one.
 */
static int propagate_mount_v2(struct mount_info *mi)
{
	struct mount_info *t;

	list_for_each_entry(t, &mi->mnt_bind, mnt_bind) {
		if (t->mounted)
			continue;
		if (t->bind)
			continue;
		if (!issubpath(t->root, mi->root))
			continue;
		pr_debug("\t\tPropagate %d to %d\n", mi->mnt_id, t->mnt_id);
		t->bind = mi;
		t->s_dev_rt = mi->s_dev_rt;
	}

	return 0;
}

/*
 * Mounts first mount of superblock
 */
static int do_new_mount_v2(struct mount_info *mi)
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
		pr_perror("Can't mount at %s", mi->plain_mountpoint);
		return -1;
	}

	/*
	 * Mount-v2 relies that before mount tree is constructed all mounts
	 * should remain private. Newly created mounts can become non-private
	 * initially depending on parent/source sharing, let's be as explicit
	 * as possible here and make it obvious that mount becomes private.
	 */
	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		return -1;
	}

	if (tp->restore && tp->restore(mi))
		return -1;

	if (remount_ro) {
		int fd;

		fd = open(mi->plain_mountpoint, O_PATH);
		if (fd < 0) {
			pr_perror("Unable to open %s", mi->plain_mountpoint);
			return -1;
		}
		sflags |= MS_RDONLY | MS_REMOUNT;
		if (userns_call(apply_sb_flags, 0, &sflags, sizeof(sflags), fd)) {
			pr_perror("Unable to apply mount flags %d for %s", mi->sb_flags, mi->plain_mountpoint);
			close(fd);
			return -1;
		}
		close(fd);
	}

	if (mflags && mount(NULL, mi->plain_mountpoint, NULL, MS_REMOUNT | MS_BIND | mflags, NULL)) {
		pr_perror("Unable to apply bind-mount options");
		return -1;
	}

	mi->mounted = true;
	return 0;
}

/*
 * Does simple bindmount, but via new kernel mount api,
 * which also handles autofs and symlink without resolving.
 */
static int __do_bind_mount_v2(char *from, char *to)
{
	int detached_fd;

	detached_fd = sys_open_tree(AT_FDCWD, from, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE);
	if (detached_fd == -1) {
		pr_perror("Failed to open_tree %s", from);
		return -1;
	}

	if (sys_move_mount(detached_fd, "", AT_FDCWD, to, MOVE_MOUNT_F_EMPTY_PATH)) {
		pr_perror("Failed to move_mount from %s to %s", from, to);
		close(detached_fd);
		return -1;
	}
	close(detached_fd);

	return 0;
}

LIST_HEAD(deleted_mounts);

/*
 * Bind-mounts all later mounts of superblock from first one,
 * also handles first mounts of mountpoint external mounts.
 */
static int do_bind_mount_v2(struct mount_info *mi)
{
	char *root = NULL, *cut_root, rpath[PATH_MAX];
	unsigned long mflags;
	int exit_code = -1;
	char *mnt_path = NULL;
	int level = 0;

	if (mi->need_plugin) {
		if (restore_ext_mount(mi))
			return -1;
		goto out;
	}

	if (mnt_is_nodev_external(mi)) {
		root = mi->external;
		goto do_bind;
	}

	cut_root = get_relative_path(mi->root, mi->bind->root);
	if (!cut_root) {
		pr_err("Failed to find root for %d in our supposed bind %d\n", mi->mnt_id, mi->bind->mnt_id);
		return -1;
	}

	/*
	 * Mount ->private can be initialized on fstype->mount() callback,
	 * which is called for first mount of superblock in do_new_mount().
	 * Also ->private have to be copied to all other mounts of superblock
	 * to provide users of it with actual data.
	 */
	mi->private = mi->bind->private;

	mnt_path = mi->bind->plain_mountpoint;

	if (cut_root[0]) {
		snprintf(rpath, sizeof(rpath), "%s/%s", mnt_path, cut_root);
		root = rpath;
	} else {
		root = mnt_path;
	}
do_bind:
	pr_info("\tBind %s to %s\n", root, mi->plain_mountpoint);

	if (unlikely(mi->deleted)) {
		level = make_parent_dirs_if_need(-1, root);
		if (level < 0)
			goto err;

		if (mi->is_dir) {
			if (mkdir(root, 0600)) {
				pr_perror("Can't re-create deleted directory %s", root);
				goto err;
			}
		} else {
			int fd = open(root, O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (fd < 0) {
				pr_perror("Can't re-create deleted file %s", root);
				goto err;
			}
			close(fd);
		}
	}

	if (__do_bind_mount_v2(root, mi->plain_mountpoint))
		goto err;

	/*
	 * Mount-v2 relies that before mount tree is constructed all mounts
	 * should remain private. Newly created mounts can become non-private
	 * initially depending on parent/source sharing, let's be as explicit
	 * as possible here and make it obvious that mount becomes private.
	 */
	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		goto err;
	}

	mflags = mi->flags & (~MS_PROPAGATE);
	if (!mi->bind || mflags != (mi->bind->flags & (~MS_PROPAGATE)))
		if (mount(NULL, mi->plain_mountpoint, NULL, MS_BIND | MS_REMOUNT | mflags, NULL)) {
			pr_perror("Can't bind remount 0x%lx at %s", mflags, mi->plain_mountpoint);
			goto err;
		}

	if (mi->deleted) {
		/*
		 * Deleted mounts can't be moved, will delete source after
		 * moving to proper position in the mount tree FIXME.
		 */
		mi->deleted_level = level;
		level = 0;
		list_add(&mi->deleted_list, &deleted_mounts);
	}
out:
	mi->mounted = true;
	exit_code = 0;
err:
	if (level)
		rm_parent_dirs(-1, root, level);

	return exit_code;
}

/* Mounts root container mount. */
static int do_mount_root_v2(struct mount_info *mi)
{
	unsigned long mflags = mi->flags & (~MS_PROPAGATE);
	unsigned long flags = MS_BIND;
	int fd;

	if (root_ns_mask & CLONE_NEWUSER) {
		fd = open(mi->plain_mountpoint, O_PATH);
		if (fd < 0) {
			pr_perror("Unable to open %s", mi->plain_mountpoint);
			return -1;
		}

		if (userns_call(mount_root, 0, &flags, sizeof(flags), fd)) {
			pr_err("Unable to mount %s\n", mi->plain_mountpoint);
			close(fd);
			return -1;
		}
		close(fd);
	} else {
		if (mount(opts.root, mi->plain_mountpoint, NULL, flags, NULL)) {
			pr_perror("Unable to mount %s %s (id=%d)", opts.root, mi->plain_mountpoint, mi->mnt_id);
			return -1;
		}
	}

	/*
	 * Mount-v2 relies that before mount tree is constructed all mounts
	 * should remain private. Newly created mounts can become non-private
	 * initially depending on parent/source sharing, let's be as explicit
	 * as possible here and make it obvious that mount becomes private.
	 */
	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		return -1;
	}

	if (mflags && mount(NULL, mi->plain_mountpoint, NULL, MS_REMOUNT | MS_BIND | mflags, NULL)) {
		pr_perror("Unable to apply root mount options");
		return -1;
	}

	mi->mounted = true;

	return 0;
}

/* Check if mount is ready to be mounted. */
static bool can_mount_now_v2(struct mount_info *mi)
{
	struct mount_info *root, *ext;

	/* Parent should be mounted already, that's how mnt_tree_for_each works */
	BUG_ON(mi->parent && !mi->parent->mounted);

	/* Root mounts can be mounted at any moment */
	if (rst_mnt_is_root(mi)) {
		pr_debug("%s: true as %d is global root\n", __func__, mi->mnt_id);
		return true;
	}

	/* External mounts can be mounted at any moment */
	if (mi->external) {
		pr_debug("%s: true as %d is external\n", __func__, mi->mnt_id);
		return true;
	}

	/*
	 * Container root and external mounts should go before
	 * anything which should be bindmounted from them.
	 */
	if (!mi->bind) {
		root = mnt_get_root_bind(mi);
		if (root) {
			pr_debug("%s: false as %d is bind of not mounted global root %d\n", __func__, mi->mnt_id,
				 root->mnt_id);
			return false;
		}

		ext = mnt_get_external_bind(mi);
		if (ext) {
			pr_debug("%s: false as %d is a bind of not mounted external %d\n", __func__, mi->mnt_id,
				 ext->mnt_id);
			return false;
		}
	}

	/* Non fsroot mounts can not be mounted without bind-mount */
	if (!fsroot_mounted(mi) && !mi->bind && !mi->need_plugin) {
		pr_debug("%s: false as %d is non-root without bind or plugin\n", __func__, mi->mnt_id);
		return false;
	}

	return true;
}

static int __set_unbindable_v2(struct mount_info *mi)
{
	if (mi->flags & MS_UNBINDABLE) {
		if (mount(NULL, service_mountpoint(mi), NULL, MS_UNBINDABLE, NULL)) {
			pr_perror("Failed to set mount %d unbindable", mi->mnt_id);
			return -1;
		}
	}
	return 0;
}

/*
 * Setting MS_UNBINDABLE flag is slightly delayed,
 * obviousely until we finish bind-mounting everything.
 */
static int set_unbindable_v2(void)
{
	int orig_nsfd = -1, nsfd = -1, exit_code = -1;
	struct mount_info *mi;
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		bool ns_has_unbindable = false;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		for (mi = mntinfo; mi != NULL; mi = mi->next)
			if (mi->nsid == nsid && mi->flags & MS_UNBINDABLE)
				ns_has_unbindable = true;

		if (!ns_has_unbindable)
			continue;

		nsfd = fdstore_get(nsid->mnt.nsfd_id);
		if (nsfd < 0)
			goto err;

		if (switch_ns_by_fd(nsfd, &mnt_ns_desc, orig_nsfd == -1 ? &orig_nsfd : NULL))
			goto err;
		close_safe(&nsfd);

		if (mnt_tree_for_each(nsid->mnt.mntinfo_tree, __set_unbindable_v2))
			goto err;
	}

	exit_code = 0;
err:
	if (orig_nsfd >= 0 && restore_ns(orig_nsfd, &mnt_ns_desc))
		exit_code = -1;
	close_safe(&nsfd);
	return exit_code;
}

/*
 * Detects if mount is a directory mount or file mount based on stat on
 * its mountpoint inside already mounted parent mount. This is deeply
 * integrated in plain mount creation process because before mounting
 * something plain we need to create right type of mountpoint for it.
 */
static int detect_is_dir(struct mount_info *mi)
{
	static char mountpoint[PATH_MAX];
	char *rel_path;
	struct stat st;

	if (mi->is_dir != -1)
		return 0;

	if (mi->mnt_id == HELPER_MNT_ID) {
		pr_err("Helper %s should have is_dir pre-set\n", mi->ns_mountpoint);
		return -1;
	}

	if (!mi->parent || mi->parent == root_yard_mp) {
		pr_err("Mount namespace root mount %d should have is_dir pre-set\n", mi->mnt_id);
		return -1;
	}

	if (!mi->parent->mounted) {
		pr_err("Parent mount %d of %d should be mounted\n", mi->parent->mnt_id, mi->mnt_id);
		return -1;
	}

	rel_path = get_relative_path(mi->ns_mountpoint, mi->parent->ns_mountpoint);
	if (!rel_path) {
		pr_err("Child-parent mountpoint mismatch %d:%s %d:%s\n", mi->mnt_id, mi->ns_mountpoint,
		       mi->parent->mnt_id, mi->parent->ns_mountpoint);
		return -1;
	}

	snprintf(mountpoint, sizeof(mountpoint), "%s%s%s", mi->parent->plain_mountpoint, rel_path[0] ? "/" : "",
		 rel_path);
	if (stat(mountpoint, &st)) {
		pr_perror("Can't stat mountpoint %s", mountpoint);
		return -1;
	}

	if (S_ISDIR(st.st_mode))
		mi->is_dir = true;
	else
		mi->is_dir = false;

	pr_debug("Mount %d is detected as %s-mount\n", mi->mnt_id, mi->is_dir ? "dir" : "file");
	return 0;
}

static int create_plain_mountpoint(struct mount_info *mi)
{
	BUG_ON(mi->is_dir == -1);

	pr_debug("Create plain mountpoint %s for %d\n", mi->plain_mountpoint, mi->mnt_id);
	if (mi->is_dir) {
		if (mkdir(mi->plain_mountpoint, 0600)) {
			pr_perror("Unable to mkdir mountpoint %s", mi->plain_mountpoint);
			return -1;
		}
	} else {
		int fd;

		fd = creat(mi->plain_mountpoint, 0600);
		if (fd < 0) {
			pr_perror("Unable to create mountpoint %s", mi->plain_mountpoint);
			return -1;
		}
		close(fd);
	}

	return 0;
}

/*
 * At this point we already have a mount in service mount namespace now we
 * bind-mount it to the final restored mount namespace via new kernel mount
 * API.
 */
static int do_mount_in_right_mntns(struct mount_info *mi)
{
	int nsfd = -1, orig_nsfd = -1, detached_fd = -1, exit_code = -1;

	if (!mi->nsid)
		return 0;

	detached_fd =
		sys_open_tree(AT_FDCWD, mi->plain_mountpoint, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE);
	if (detached_fd == -1) {
		pr_perror("Failed to open_tree %s", mi->plain_mountpoint);
		goto err;
	}

	nsfd = fdstore_get(mi->nsid->mnt.nsfd_id);
	if (nsfd < 0)
		goto err;

	if (switch_ns_by_fd(nsfd, &mnt_ns_desc, &orig_nsfd))
		goto err;

	if (create_plain_mountpoint(mi))
		goto err;

	if (sys_move_mount(detached_fd, "", AT_FDCWD, mi->plain_mountpoint, MOVE_MOUNT_F_EMPTY_PATH)) {
		pr_perror("Failed to cross-mntns move_mount plain mount %d", mi->mnt_id);
		goto err;
	}

	exit_code = 0;
err:
	if (orig_nsfd >= 0 && restore_ns(orig_nsfd, &mnt_ns_desc))
		exit_code = -1;
	close_safe(&nsfd);
	close_safe(&detached_fd);
	return exit_code;
}

static int do_mount_one_v2(struct mount_info *mi)
{
	int ret;

	if (mi->mounted)
		return 0;

	if (!can_mount_now_v2(mi)) {
		pr_debug("Postpone mount %d\n", mi->mnt_id);
		return 1;
	}

	if (detect_is_dir(mi))
		return -1;

	if (create_plain_mountpoint(mi))
		return -1;

	pr_debug("\tMounting %s @%d (%d)\n", mi->fstype->name, mi->mnt_id, mi->need_plugin);

	if (rst_mnt_is_root(mi)) {
		if (opts.root == NULL) {
			pr_err("The --root option is required to restore a mount namespace\n");
			return -1;
		}
		ret = do_mount_root_v2(mi);
	} else if (!mi->bind && !mi->need_plugin && (!mi->external || !strcmp(mi->external, EXTERNAL_DEV_MOUNT))) {
		ret = do_new_mount_v2(mi);
	} else {
		ret = do_bind_mount_v2(mi);
	}

	if (ret == 0 && fetch_rt_stat(mi, mi->plain_mountpoint))
		return -1;

	if (ret == 0 && propagate_mount_v2(mi))
		return -1;

	if (mi->fstype->code == FSTYPE__UNSUPPORTED) {
		struct statfs st;

		if (statfs(mi->plain_mountpoint, &st)) {
			pr_perror("Unable to statfs %s", mi->plain_mountpoint);
			return -1;
		}
		if (st.f_type == BTRFS_SUPER_MAGIC)
			mi->fstype = find_fstype_by_name("btrfs");
	}

	if (ret == 0 && do_mount_in_right_mntns(mi))
		return -1;

	return ret;
}

static int populate_mnt_ns_v2(void)
{
	if (make_yard(mnt_roots))
		return -1;

	if (mnt_tree_for_each(root_yard_mp, do_mount_one_v2))
		return -1;

	return set_unbindable_v2();
}

/*
 * This function moves plain mounts into actual mount tree.
 *
 * Mounts in children list are sorted the way that sibling overmount goes after
 * all siblings which it overmounts (see __mnt_resort_children). The function
 * mnt_tree_for_each is effectively DFS (in case we don't postpone), thus all
 * descendants of all mounts which we sibling-overmount are mounted before us.
 * Be careful, we can't postpone (return >0) from this function because of it.
 */
static int move_mount_to_tree(struct mount_info *mi)
{
	int fd;

	fd = open(mi->mountpoint, O_PATH);
	if (fd < 0) {
		pr_perror("Failed to open real mountpoint of %d", mi->mnt_id);
		return -1;
	}

	mi->mp_fd_id = fdstore_add(fd);
	close(fd);
	if (mi->mp_fd_id < 0) {
		pr_err("Can't add mountpoint of mount %d to fdstore\n", mi->mnt_id);
		return -1;
	}

	pr_info("Move mount %d from %s to %s\n", mi->mnt_id, mi->plain_mountpoint, mi->mountpoint);
	if (sys_move_mount(AT_FDCWD, mi->plain_mountpoint, AT_FDCWD, mi->mountpoint, 0)) {
		pr_perror("Failed to move mount %d from %s to %s", mi->mnt_id, mi->plain_mountpoint, mi->mountpoint);
		return -1;
	}

	fd = open(mi->mountpoint, O_PATH);
	if (fd < 0) {
		pr_perror("Failed to open real mountpoint of %d", mi->mnt_id);
		return -1;
	}

	mi->mnt_fd_id = fdstore_add(fd);
	close(fd);
	if (mi->mnt_fd_id < 0) {
		pr_err("Can't add mount %d fd to fdstore\n", mi->mnt_id);
		return -1;
	}

	return 0;
}

static int assemble_tree_from_plain_mounts(struct ns_id *nsid)
{
	return mnt_tree_for_each(nsid->mnt.mntinfo_tree, move_mount_to_tree);
}

/*
 * With MOVE_MOUNT_SET_GROUP source mount should have wider root than
 * destination, thus let's choose widest mount from group as first.
 */
static struct mount_info *get_first_mount(struct sharing_group *sg)
{
	struct mount_info *first = NULL, *tmp;
	int min_len = 0;

	list_for_each_entry(tmp, &sg->mnt_list, mnt_sharing) {
		int len = strlen(tmp->root);

		if (!first || len < min_len) {
			first = tmp;
			min_len = len;
		}
	}

	return first;
}

struct set_group_arg {
	int src_id;
	char source[PATH_MAX];
	int dst_id;
};

static int __move_mount_set_group(void *arg, int dfd, int pid)
{
	struct set_group_arg *sga = (struct set_group_arg *)arg;
	int src_fd, dst_fd, exit_code = -1;

	if (sga->src_id != -1) {
		src_fd = fdstore_get(sga->src_id);
		BUG_ON(src_fd < 0);
	} else {
		char *source_mp;

		BUG_ON(sga->source[0] == '\0');
		/*
		 * Source path should not always be a mountpoint as we
		 * automatically resolve it to mountpoint below.
		 */
		source_mp = resolve_mountpoint(sga->source);
		if (!source_mp) {
			pr_err("Failed to find %s mountpoint\n", sga->source);
			return -1;
		}

		src_fd = open(source_mp, O_PATH);
		if (src_fd < 0) {
			pr_perror("Failed to open %s mountpoint", source_mp);
			xfree(source_mp);
			return -1;
		}
		xfree(source_mp);
	}

	dst_fd = fdstore_get(sga->dst_id);
	BUG_ON(dst_fd < 0);

	/* Copy shared_id of the source */
	if (sys_move_mount(src_fd, "", dst_fd, "",
			   MOVE_MOUNT_SET_GROUP | MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)) {
		pr_perror("Failed to copy sharing from %d:%s to %d", sga->src_id, sga->source ?: "<none>", sga->dst_id);
		goto err;
	}

	exit_code = 0;
err:
	close(src_fd);
	close(dst_fd);
	return exit_code;
}

/*
 * Copy sharing between mounts passing mountpoint fds via fdstore ids. Also it
 * is possible (for external mounts) to pass path on mountpoint via source path,
 * it would resolve to mountpoint automatically.
 */
static int move_mount_set_group(int src_id, char *source, int dst_id)
{
	struct set_group_arg sga = {
		.src_id = src_id,
		.dst_id = dst_id,
	};

	sga.source[0] = '\0';
	if (source) {
		if (snprintf(sga.source, sizeof(sga.source), "%s", source) >= sizeof(sga.source)) {
			pr_err("Source %s is too long\n", source);
			return -1;
		}
	}

	if (userns_call(__move_mount_set_group, 0, &sga, sizeof(sga), -1))
		return -1;

	return 0;
}

static int restore_one_sharing(struct sharing_group *sg, struct mount_info *target)
{
	int nsfd = -1, orig_nsfd = -1, exit_code = -1;
	char target_path[PATH_MAX];
	int target_fd = -1;

	if (!sg->master_id && !sg->shared_id)
		return 0;

	target_fd = fdstore_get(target->mnt_fd_id);
	BUG_ON(target_fd < 0);
	snprintf(target_path, sizeof(target_path), "/proc/self/fd/%d", target_fd);

	/* Restore target's master_id from shared_id of the source */
	if (sg->master_id) {
		if (sg->parent) {
			struct mount_info *first;

			/* Get shared_id from parent sharing group */
			first = get_first_mount(sg->parent);
			if (move_mount_set_group(first->mnt_fd_id, NULL, target->mnt_fd_id)) {
				pr_err("Failed to copy sharing from %d to %d\n", first->mnt_id, target->mnt_id);
				goto err;
			}
		} else {
			/*
			 * External slavery. We rely on the user to give us the
			 * right source for external mount with all proper
			 * sharing options setup (it should be either shared
			 * or non-shared slave). If source is a private mount
			 * we would fail.
			 */
			if (move_mount_set_group(-1, sg->source, target->mnt_fd_id)) {
				pr_err("Failed to copy sharing from source %s to %d\n", sg->source, target->mnt_id);
				goto err;
			}
		}
	}

	nsfd = fdstore_get(target->nsid->mnt.nsfd_id);
	if (nsfd < 0)
		goto err;

	if (switch_ns_by_fd(nsfd, &mnt_ns_desc, &orig_nsfd))
		goto err;

	if (sg->master_id) {
		/* Convert shared_id to master_id */
		if (mount(NULL, target_path, NULL, MS_SLAVE, NULL)) {
			pr_perror("Failed to make mount %d slave", target->mnt_id);
			goto err;
		}
	}

	/* Restore target's shared_id */
	if (sg->shared_id) {
		if (mount(NULL, target_path, NULL, MS_SHARED, NULL)) {
			pr_perror("Failed to make mount %d shared", target->mnt_id);
			goto err;
		}
	}
	exit_code = 0;
err:
	close_safe(&target_fd);
	close_safe(&nsfd);
	if (orig_nsfd >= 0 && restore_ns(orig_nsfd, &mnt_ns_desc))
		exit_code = -1;
	return exit_code;
}

static int restore_one_sharing_group(struct sharing_group *sg)
{
	struct mount_info *first, *other;

	first = get_first_mount(sg);

	if (restore_one_sharing(sg, first))
		return -1;

	/* Restore sharing for other mounts from the sharing group */
	list_for_each_entry(other, &sg->mnt_list, mnt_sharing) {
		if (other == first)
			continue;

		if (is_sub_path(other->root, first->root)) {
			if (move_mount_set_group(first->mnt_fd_id, NULL, other->mnt_fd_id)) {
				pr_err("Failed to copy sharing from %d to %d\n", first->mnt_id, other->mnt_id);
				return -1;
			}
		} else {
			/*
			 * Case where mounts of this sharing group don't have common root.
			 * For instance we can create two sub-directories .a and .b in some
			 * shared mount, bindmount them separately somethere and umount the
			 * original mount. Now we have both bindmounts shared between each
			 * other. Kernel only allows to copy sharing between mounts when
			 * source root contains destination root, which is not true for
			 * these two, so we can't just copy from first to other.
			 *
			 * For external sharing (!sg->parent) with only master_id (shared_id
			 * == 0) we can workaround this by copying from their external source
			 * instead (same as we did for a first mount).
			 *
			 * This is a w/a runc usecase, see https://github.com/opencontainers/runc/pull/3442
			 */
			if (!sg->parent && !sg->shared_id) {
				if (restore_one_sharing(sg, other))
					return -1;
			} else {
				pr_err("Can't copy sharing from %d[%s] to %d[%s]\n", first->mnt_id, first->root,
				       other->mnt_id, other->root);
				return -1;
			}
		}
	}

	return 0;
}

static struct sharing_group *sharing_group_next(struct sharing_group *sg)
{
	if (!list_empty(&sg->children))
		return list_entry(sg->children.next, struct sharing_group, siblings);

	while (sg->parent) {
		if (sg->siblings.next == &sg->parent->children)
			sg = sg->parent;
		else
			return list_entry(sg->siblings.next, struct sharing_group, siblings);
	}

	return NULL;
}

static int restore_mount_sharing_options(void)
{
	struct sharing_group *sg;

	list_for_each_entry(sg, &sharing_groups, list) {
		struct sharing_group *t;

		if (sg->parent)
			continue;

		/* Handle dependent sharing groups in tree order */
		for (t = sg; t != NULL; t = sharing_group_next(t)) {
			if (restore_one_sharing_group(t))
				return -1;
		}
	}

	return 0;
}

static int remove_source_of_deleted_mount(struct mount_info *mi)
{
	char *cut_root, path[PATH_MAX], *root;

	BUG_ON(!mi->deleted || !mi->bind);

	cut_root = get_relative_path(mi->root, mi->bind->root);
	if (!cut_root) {
		pr_err("Failed to find root for %d in our supposed bind %d\n", mi->mnt_id, mi->bind->mnt_id);
		return -1;
	}

	if (cut_root[0]) {
		snprintf(path, sizeof(path), "%s/%s", mi->bind->plain_mountpoint, cut_root);
		root = path;
	} else {
		root = mi->bind->plain_mountpoint;
	}

	if (mi->is_dir) {
		if (rmdir(root)) {
			pr_perror("Can't remove deleted directory %s", root);
			return -1;
		}
	} else {
		if (unlink(root)) {
			pr_perror("Can't unlink deleted file %s", root);
			return -1;
		}
	}

	if (mi->deleted_level)
		rm_parent_dirs(-1, root, mi->deleted_level);

	return 0;
}

/* Delay making mounts deleted until we've restored sharing groups */
static int remove_sources_of_deleted_mounts(void)
{
	struct mount_info *mi;
	int ret = 0;

	list_for_each_entry(mi, &deleted_mounts, deleted_list) {
		if (remove_source_of_deleted_mount(mi))
			ret = -1;
	}

	return ret;
}

static int get_empty_mntns(void)
{
	int orig_nsfd, nsfd = -1;

	orig_nsfd = open_proc(PROC_SELF, "ns/mnt");
	if (orig_nsfd < 0)
		return -1;

	/* Create the new mount namespace */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a new mntns");
		close(orig_nsfd);
		return -1;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		pr_perror("Can't remount \"/\" with MS_PRIVATE");
		goto err;
	}

	if (make_yard(mnt_roots))
		goto err;

	if (cr_pivot_root(mnt_roots))
		goto err;

	if (mkdirpat(AT_FDCWD, mnt_roots, 0777)) {
		pr_err("Failed to setup root yard in empty mntns\n");
		goto err;
	}

	nsfd = open_proc(PROC_SELF, "ns/mnt");
err:
	if (restore_ns(orig_nsfd, &mnt_ns_desc))
		close_safe(&nsfd);
	return nsfd;
}

/* Create almost empty mount namespaces only with root yard precreated */
static int pre_create_mount_namespaces(void)
{
	int orig_nsfd = -1, nsfd = -1, empty_mntns, exit_code = -1;
	char path[PATH_MAX];
	struct ns_id *nsid;

	empty_mntns = get_empty_mntns();
	if (empty_mntns == -1) {
		pr_err("Failed to create empty mntns\n");
		goto err;
	}

	/* restore mount namespaces */
	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (switch_ns_by_fd(empty_mntns, &mnt_ns_desc, orig_nsfd == -1 ? &orig_nsfd : NULL))
			goto err;

		/* Create the new mount namespace */
		if (unshare(CLONE_NEWNS)) {
			pr_perror("Unable to create a new mntns");
			goto err;
		}

		nsfd = open_proc(PROC_SELF, "ns/mnt");
		if (nsfd < 0)
			goto err;

		/* Pin new mntns with a file descriptor */
		nsid->mnt.nsfd_id = fdstore_add(nsfd);
		close(nsfd);
		if (nsid->mnt.nsfd_id < 0) {
			pr_err("Can't add mntns fd to fdstore\n");
			goto err;
		}

		if (make_yard(mnt_roots))
			goto err;

		print_ns_root(nsid, 0, path, sizeof(path));
		if (mkdir(path, 0600)) {
			pr_perror("Unable to create %s", path);
			goto err;
		}
	}

	exit_code = 0;
err:
	if (orig_nsfd >= 0 && restore_ns(orig_nsfd, &mnt_ns_desc))
		exit_code = -1;
	close_safe(&empty_mntns);
	return exit_code;
}

/*
 * Assemble the mount tree for each restored mount namespace
 * from pre-created plain mounts.
 */
static int assemble_mount_namespaces(void)
{
	int orig_nsfd = -1, nsfd = -1, rootfd = -1, exit_code = -1;
	char path[PATH_MAX];
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		nsfd = fdstore_get(nsid->mnt.nsfd_id);
		if (nsfd < 0)
			goto err;

		if (switch_ns_by_fd(nsfd, &mnt_ns_desc, orig_nsfd == -1 ? &orig_nsfd : NULL)) {
			close(nsfd);
			goto err;
		}
		close(nsfd);

		if (assemble_tree_from_plain_mounts(nsid))
			goto err;

		/* Set its root */
		print_ns_root(nsid, 0, path, sizeof(path) - 1);
		if (cr_pivot_root(path))
			goto err;

		/* root fd is used to restore file mappings */
		rootfd = open_proc(PROC_SELF, "root");
		if (rootfd < 0)
			goto err;
		nsid->mnt.root_fd_id = fdstore_add(rootfd);
		if (nsid->mnt.root_fd_id < 0) {
			pr_err("Can't add root fd to fdstore\n");
			close(rootfd);
			goto err;
		}
		close(rootfd);
	}

	exit_code = 0;
err:
	if (orig_nsfd >= 0 && restore_ns(orig_nsfd, &mnt_ns_desc))
		exit_code = -1;
	return exit_code;
}

/* The main entry point of mount-v2 for creating mounts */
int prepare_mnt_ns_v2(void)
{
	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
	if (!opts.has_binfmt_misc && !list_empty(&binfmt_misc_list)) {
		/*
		 * Add to root yard along with other plain mounts and mntns
		 * directories. This mount would be created and restored by
		 * generic mount creation code, but it would never be moved to
		 * any restored mount namespaces.
		 */
		if (!add_cr_time_mount(root_yard_mp, "binfmt_misc", "binfmt_misc", 0, true))
			return -1;
	}
#endif

	if (validate_mounts(mntinfo, false))
		return -1;

	if (pre_create_mount_namespaces())
		return -1;

	if (populate_mnt_ns_v2())
		return -1;

	if (assemble_mount_namespaces())
		return -1;

	if (restore_mount_sharing_options())
		return -1;

	return remove_sources_of_deleted_mounts();
}
