#include <stdio.h>
#include <string.h>

#include "mountinfo.h"
#include "fs.h"
#include "xmalloc.h"

/*
 * mountinfo contains mangled paths. space, tab and back slash were replaced
 * with usual octal escape. This function replaces these symbols back.
 */
static void cure_path(char *path)
{
	int i, len, off = 0;

	if (strchr(path, '\\') == NULL) /* fast path */
		return;

	len = strlen(path);
	for (i = 0; i < len; i++) {
		if (!strncmp(path + i, "\\040", 4)) {
			path[i - off] = ' ';
			goto replace;
		} else if (!strncmp(path + i, "\\011", 4)) {
			path[i - off] = '\t';
			goto replace;
		} else if (!strncmp(path + i, "\\134", 4)) {
			path[i - off] = '\\';
			goto replace;
		}
		if (off)
			path[i - off] = path[i];
		continue;
	replace:
		off += 3;
		i += 3;
	}
	path[len - off] = 0;
}

static struct mountinfo_zdtm *mountinfo_zdtm_alloc(struct mntns_zdtm *mntns)
{
	struct mountinfo_zdtm *new;

	new = xzalloc(sizeof(struct mountinfo_zdtm));
	if (new)
		list_add_tail(&new->list, &mntns->mountinfo_list);
	return new;
}

static void mountinfo_zdtm_free(struct mountinfo_zdtm *mountinfo)
{
	list_del(&mountinfo->list);
	xfree(mountinfo->mountpoint);
	xfree(mountinfo->root);
	xfree(mountinfo->fstype);
	xfree(mountinfo);
}

static void mountinfo_zdtm_free_all(struct mntns_zdtm *mntns)
{
	struct mountinfo_zdtm *mountinfo, *tmp;

	list_for_each_entry_safe(mountinfo, tmp, &mntns->mountinfo_list, list)
		mountinfo_zdtm_free(mountinfo);
}

#define BUF_SIZE 4096
char buf[BUF_SIZE];

int mntns_parse_mountinfo(struct mntns_zdtm *mntns)
{
	FILE *f;
	int ret;

	INIT_LIST_HEAD(&mntns->mountinfo_list);

	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		pr_perror("Failed to open mountinfo");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, f)) {
		struct mountinfo_zdtm *new;
		unsigned int kmaj, kmin;
		char *str, *hyphen, *shared, *master;
		int n;

		new = mountinfo_zdtm_alloc(mntns);
		if (!new) {
			pr_perror("Failed to alloc mountinfo_zdtm");
			goto free;
		}

		ret = sscanf(buf, "%i %i %u:%u %ms %ms %*s %n", &new->mnt_id, &new->parent_mnt_id, &kmaj, &kmin,
			     &new->root, &new->mountpoint, &n);
		if (ret != 6) {
			pr_perror("Failed to parse mountinfo line \"%s\"", buf);
			goto free;
		}
		cure_path(new->root);
		cure_path(new->mountpoint);
		new->s_dev = MKKDEV(kmaj, kmin);

		str = buf + n;
		hyphen = strstr(buf, " - ");
		if (!hyphen) {
			pr_perror("Failed to find \" - \" in mountinfo line \"%s\"", buf);
			goto free;
		}
		*hyphen++ = '\0';

		shared = strstr(str, "shared:");
		if (shared)
			new->shared_id = atoi(shared + 7);
		master = strstr(str, "master:");
		if (master)
			new->master_id = atoi(master + 7);

		ret = sscanf(hyphen, "- %ms", &new->fstype);
		if (ret != 1) {
			pr_perror("Failed to parse fstype in mountinfo tail \"%s\"", hyphen);
			goto free;
		}
	}

	fclose(f);
	return 0;
free:
	mountinfo_zdtm_free_all(mntns);
	fclose(f);
	return -1;
}

void mntns_free_all(struct mntns_zdtm *mntns)
{
	mountinfo_zdtm_free_all(mntns);
}
