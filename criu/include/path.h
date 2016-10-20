#ifndef __CR_PATH_H__
#define __CR_PATH_H__

#include "namespaces.h"
#include "pstree.h"

/* Asolute paths are used on dump and relative paths are used on restore */
static inline int is_root(char *p)
{
	return (!strcmp(p, "/"));
}

/* True for the root mount (the topmost one) */
static inline int is_root_mount(struct mount_info *mi)
{
	return mi->parent == NULL && mi->nsid->id == root_item->ids->mnt_ns_id;
}

/*
 * True if the mountpoint target is root on its FS.
 *
 * This is used to determine whether we need to postpone
 * mounting. E.g. one can bind mount some subdir from a
 * disk, and in this case we'll have to get the root disk
 * mount first, then bind-mount it. See do_mount_one().
 */
static inline int fsroot_mounted(struct mount_info *mi)
{
	return is_root(mi->root);
}

char *cut_root_for_bind(char *target_root, char *source_root);

/*
 * Get a mount point for a sibling of m if m->parent and p are in the same
 * shared group.
 */
char *mnt_get_sibling_path(struct mount_info *m,
			   struct mount_info *p, char *buf, int len);

#endif
