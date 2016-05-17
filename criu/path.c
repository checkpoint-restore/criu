#include <string.h>
#include <stdio.h>

#include "mount.h"
#include "path.h"
#include "bug.h"

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
