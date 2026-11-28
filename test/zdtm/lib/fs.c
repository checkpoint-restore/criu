#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "zdtmtst.h"
#include "fs.h"
#include "mountinfo.h"

struct mountinfo_zdtm *get_cwd_mnt_info(void)
{
	struct mountinfo_zdtm *mi, *best = NULL;
	size_t len, best_len = 0;
	MNTNS_ZDTM(mntns);
	char *cwd;

	cwd = get_current_dir_name();
	if (!cwd)
		return NULL;

	if (mntns_parse_mountinfo(&mntns))
		goto out;

	list_for_each_entry(mi, &mntns.mountinfo_list, list) {
		len = strlen(mi->mountpoint);
		if (!strncmp(mi->mountpoint, cwd, len) && len > best_len) {
			best_len = len;
			best = mi;
		}
	}

	/* Detach the result so that mntns_free_all() keeps it */
	if (best)
		list_del_init(&best->list);
out:
	mntns_free_all(&mntns);
	free(cwd);
	return best;
}

int get_cwd_check_perm(char **result)
{
	char *cwd;
	*result = 0;
	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("failed to get current directory");
		return -1;
	}

	if (access(cwd, X_OK)) {
		pr_err("access check for bit X for current dir path '%s' "
		       "failed for uid:%d,gid:%d, error: %d(%s). "
		       "Bit 'x' should be set in all path components of "
		       "this directory\n",
		       cwd, getuid(), getgid(), errno, strerror(errno));
		free(cwd);
		return -1;
	}

	*result = cwd;
	return 0;
}
