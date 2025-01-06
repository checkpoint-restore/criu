#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "int.h"
#include "mount.h"
#include "path.h"
#include "log.h"
#include "util.h"
#include "common/bug.h"

char *cut_root_for_bind(char *target_root, char *source_root)
{
	int tok = 0;
	char *path = NULL;
	/*
	 * Cut common part of root.
	 * For non-root binds the source is always "/" (checked)
	 * so this will result in this slash removal only.
	 */
	while (target_root[tok] == source_root[tok]) {
		tok++;
		if (source_root[tok] == '\0') {
			path = target_root + tok;
			goto out;
		}
		if (target_root[tok] == '\0') {
			path = source_root + tok;
			goto out;
		}
	}

	return NULL;
out:
	BUG_ON(path == NULL);
	if (path[0] == '/')
		path++;

	return path;
}

char *mnt_get_sibling_path(struct mount_info *m, struct mount_info *p, char *buf, int len)
{
	struct mount_info *pa = m->parent;
	char *rpath, fsrpath[PATH_MAX];

	if (pa == NULL)
		return NULL;

	rpath = get_relative_path(m->ns_mountpoint, pa->ns_mountpoint);
	if (!rpath) {
		pr_warn("child - parent mountpoint mismatch %s - %s\n", m->ns_mountpoint, pa->ns_mountpoint);
		return NULL;
	}

	if (snprintf(fsrpath, sizeof(fsrpath), "%s/%s", pa->root, rpath) >= sizeof(fsrpath)) {
		pr_warn("snrptintf truncation \"%s / %s\"\n", pa->root, rpath);
		return NULL;
	}

	rpath = get_relative_path(fsrpath, p->root);
	if (!rpath)
		return NULL;

	if (snprintf(buf, len, "%s/%s", p->ns_mountpoint, rpath) >= sizeof(fsrpath)) {
		pr_warn("snrptintf truncation \"%s / %s\"\n", p->ns_mountpoint, rpath);
		return NULL;
	}

	return buf;
}
