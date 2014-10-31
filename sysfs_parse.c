#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>

#include "cr_options.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "files.h"
#include "proc_parse.h"
#include "util.h"
#include "sysfs_parse.h"
#include "namespaces.h"

/*
 * Currently, there are two kernel problems dealing with AUFS
 * filesystems.  Until these problems are fixed in the kernel,
 * we have AUFS support in CRIU to handle the following issues:
 *
 * 1) /proc/<pid>/mountinfo: The problem is that for AUFS the root field
 * of the root entry is missing the pathname (it's only /).  For example:
 *
 * 90 61 0:33 / / rw,relatime - aufs none rw,si=4476a910a24617e6
 *
 * To handle this issue, the user has to specify the root of the AUFS
 * filesystem with the --root command line option.
 *
 * 2) /proc/<pid>/map_files: The symlinks are absolute pathnames of the
 * corresponding *physical* files in the branch they exist.  For example,
 * for a Docker container using AUFS, a symlink would look like:
 * 400000-489000 -> /var/lib/docker/aufs/diff/<LAYER_ID>/bin/<cmd>
 *
 * Therefore, when we use the link file descriptor vm_file_fd in
 * dump_one_reg_file() to read the link, we get the file's physical
 * absolute pathname which does not exist relative to the root of the
 * mount namespace and even if we used its relative pathname, the dev:ino
 * values would be different from the physical file's dev:ino causing the
 * dump to fail.
 *
 * To handle this issue, we figure out the "correct" paths when parsing
 * map_files and save it for later use.  See fixup_aufs_vma_fd() for
 * details.
 */

struct ns_id *aufs_nsid;
static char **aufs_branches;

/*
 * Parse out and save the AUFS superblock info in the
 * given buffer.
 */
static int parse_aufs_sbinfo(struct mount_info *mi, char *sbinfo, int len)
{
	char *cp;
	int n;

	cp = strstr(mi->options, "si=");
	if (!cp) {
		pr_err("Cannot find sbinfo in option string %s\n", mi->options);
		return -1;
	}

	/* all ok, copy */
	if (len < 4) {		/* 4 for "si_" */
		pr_err("Buffer of %d bytes too small for sbinfo\n", len);
		return -1;
	}
	strcpy(sbinfo, "si_");
	n = 3;
	sbinfo += n;
	cp += n;
	while (isxdigit(*cp) && n < len) {
		*sbinfo++ = *cp++;
		n++;
	}
	if (n >= len) {
		pr_err("Sbinfo in options string %s too long\n", mi->options);
		return -1;
	}
	*sbinfo = '\0';
	return 0;
}

/*
 * If the specified path is in a branch, replace it
 * with pathname from root.
 */
static int fixup_aufs_path(char *path, int size)
{
	char rpath[PATH_MAX];
	int n;
	int blen;

	if (aufs_branches == NULL) {
		pr_err("No aufs branches to search for %s\n", path);
		return -1;
	}

	for (n = 0; aufs_branches[n] != NULL; n++) {
		blen = strlen(aufs_branches[n]);
		if (!strncmp(path, aufs_branches[n], blen))
			break;
	}

	if (aufs_branches[n] == NULL)
		return 0;	/* not in a branch */

	n = snprintf(rpath, PATH_MAX, "%s", &path[blen]);
	if (n >= min(PATH_MAX, size)) {
		pr_err("Not enough space to replace %s\n", path);
		return -1;
	}

	pr_debug("Replacing %s with %s\n", path, rpath);
	strcpy(path, rpath);
	return n;
}

/*
 * Kernel stores patchnames to AUFS branches in the br<n> files in
 * the /sys/fs/aufs/si_<sbinfo> directory where <n> denotes a branch
 * number and <sbinfo> is a hexadecimal number in %lx format. For
 * example:
 *
 *     $ cat /sys/fs/aufs/si_f598876b087ed883/br0
 *     /path/to/branch0/directory=rw
 *
 * This function sets up an array of pointers to branch pathnames.
 */
int parse_aufs_branches(struct mount_info *mi)
{
	char path[AUFSBR_PATH_LEN];
	char *cp;
	int n;
	int ret;
	unsigned int br_num;
	unsigned int br_max;
	DIR *dp;
	FILE *fp;
	struct dirent *de;

	pr_info("Collecting AUFS branch pathnames ...\n");

	if (mi->nsid == 0) {
		pr_err("No nsid to parse its aufs branches\n");
		return -1;
	}

	if (mi->nsid == aufs_nsid) {
		pr_debug("Using cached aufs branch paths for nsid %p\n", aufs_nsid);
		return 0;
	}

	if (aufs_nsid)
		free_aufs_branches();

	strcpy(path, SYSFS_AUFS);	/* /sys/fs/aufs/ */
	if (parse_aufs_sbinfo(mi, &path[sizeof SYSFS_AUFS - 1], SBINFO_LEN) < 0)
		return -1;
	if ((dp = opendir(path)) == NULL) {
		pr_perror("Cannot opendir %s", path);
		return -1;
	}

	/*
	 * Find out how many branches we have.
	 */
	br_max = 0;
	ret = 0;
	while (1) {
		errno = 0;
		if ((de = readdir(dp)) == NULL) {
			if (errno) {
				pr_perror("Cannot readdir %s", path);
				ret = -1;
			}
			break;
		}

		ret = sscanf(de->d_name, "br%d", &br_num);
		if (ret == 1 && br_num > br_max)
			br_max = br_num;
	}
	closedir(dp);
	if (ret == -1)
		return -1;

	/*
	 * Default AUFS maximum is 127, so 1000 should be plenty.
	 * If you increase the maximum to more than 3 digits,
	 * make sure to change AUFSBR_PATH_LEN accordingly.
	 */
	if (br_max > 999) {
		pr_err("Too many branches %d\n", br_max);
		return -1;
	}

	/*
	 * Allocate an array of pointers to branch pathnames to be read.
	 * Branches are indexed from 0 and we need a NULL pointer at the end.
	 */
	aufs_branches = xzalloc((br_max + 2) * sizeof (char *));
	if (!aufs_branches)
		return -1;

	/*
	 * Now read branch pathnames from the branch files.
	 */
	n = strlen(path);
	for (br_num = 0; br_num <= br_max; br_num++) {
		fp = NULL;

		ret = snprintf(&path[n], sizeof path - n, "/br%d", br_num);
		if (ret >= sizeof path - n) {
			pr_err("Buffer overrun creating path for branch %d\n", br_num);
			goto err;
		}

		if ((fp = fopen(path, "r")) == NULL) {
			pr_perror("Cannot fopen %s", path);
			goto err;
		}

		if (fscanf(fp, "%ms=", &aufs_branches[br_num]) != 1 ||
		    aufs_branches[br_num] == NULL) {
			pr_perror("Parse error reading %s", path);
			goto err;
		}

		/* chop off the trailing "=..." stuff */
		if ((cp = strchr(aufs_branches[br_num], '=')) == NULL) {
			pr_err("Bad format in branch pathname %s\n", aufs_branches[br_num]);
			goto err;
		}
		*cp = '\0';

		fclose(fp);
		/*
		 * Log branch information for extenal utitilies that
		 * want to recreate the process's AUFS filesystem
		 * before calling criu restore.
		 *
		 * DO NOT CHANGE this format!
		 */
		pr_info("%s : %s\n", path, aufs_branches[br_num]);
	}

	aufs_nsid = mi->nsid;
	return 0;

err:
	if (fp)
		fclose(fp);
	free_aufs_branches();
	return -1;
}

/*
 * AUFS support to compensate for the kernel bug
 * exposing branch pathnames in map_files.
 *
 * If the link points inside a branch, save the
 * relative pathname from the root of the mount
 * namespace as well as the full pathname from
 * globl root (/) for later use in dump_filemap()
 * and parse_smaps().
 */
int fixup_aufs_vma_fd(struct vma_area *vma)
{
	char path[PATH_MAX];
	int len;

	path[0] = '.';
	len = read_fd_link(vma->vm_file_fd, &path[1], sizeof path - 1);
	if (len < 0)
		return -1;

	len = fixup_aufs_path(&path[1], sizeof path - 1);
	if (len < 0)
		return -1;

	if (len > 0) {
		vma->aufs_rpath = xmalloc(len + 2);
		if (!vma->aufs_rpath)
			return -1;
		strcpy(vma->aufs_rpath, path);
		if (opts.root) {
			vma->aufs_fpath = xmalloc(strlen(opts.root) + 1 + len + 1);
			if (!vma->aufs_fpath)
				return -1;
			/* skip ./ in path */
			sprintf(vma->aufs_fpath, "%s/%s", opts.root, &path[2]);
		}
		pr_debug("Saved AUFS paths %s and %s\n", vma->aufs_rpath, vma->aufs_fpath);
	}

	return 0;
}

void free_aufs_branches(void)
{
	int n;

	if (aufs_branches) {
		for (n = 0; aufs_branches[n] != NULL; n++)
			xfree(aufs_branches[n]);

		xfree(aufs_branches);
		aufs_branches = NULL;
	}

	aufs_nsid = NULL;
}
