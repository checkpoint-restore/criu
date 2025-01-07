#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "zdtmtst.h"
#include "fs.h"

mnt_info_t *mnt_info_alloc(void)
{
	mnt_info_t *m = malloc(sizeof(*m));
	if (m)
		memset(m, 0, sizeof(*m));
	return m;
}

void mnt_info_free(mnt_info_t **m)
{
	if (m && *m) {
		free(*m);
		*m = NULL;
	}
}

mnt_info_t *get_cwd_mnt_info(void)
{
	int mnt_id, parent_mnt_id;
	unsigned int kmaj, kmin;
	char str[1024], *cwd;
	int ret;
	FILE *f;

	mnt_info_t *m = NULL;

	char mountpoint[PATH_MAX];
	char root[PATH_MAX];

	char *fsname = NULL;
	size_t len = 0, best_len = 0;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return NULL;

	cwd = get_current_dir_name();
	if (!cwd)
		goto err;

	m = mnt_info_alloc();
	if (!m)
		goto err;

	while (fgets(str, sizeof(str), f)) {
		char *hyphen = strchr(str, '-');
		ret = sscanf(str, "%i %i %u:%u %4095s %4095s", &mnt_id, &parent_mnt_id, &kmaj, &kmin, root, mountpoint);
		if (ret != 6 || !hyphen)
			goto err;
		ret = sscanf(hyphen + 1, " %ms", &fsname);
		if (ret != 1)
			goto err;

		len = strlen(mountpoint);
		if (!strncmp(mountpoint, cwd, len)) {
			if (len > best_len) {
				best_len = len;

				m->mnt_id = mnt_id;
				m->parent_mnt_id = parent_mnt_id;
				m->s_dev = MKKDEV(kmaj, kmin);

				strncpy(m->root, root, sizeof(m->root));
				strncpy(m->mountpoint, mountpoint, sizeof(m->mountpoint));
				strncpy(m->fsname, fsname, sizeof(m->fsname) - 1);
				m->fsname[sizeof(m->fsname) - 1] = 0;
			}
		}

		free(fsname);
		fsname = NULL;
	}

out:
	free(cwd);
	fclose(f);

	return m;

err:
	mnt_info_free(&m);
	goto out;
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
