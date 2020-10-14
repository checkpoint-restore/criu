#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check complex sharing options for mounts";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mount_complex_sharing";
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * Description for creating a single file:
 * path - path to create file in (relative to mount)
 * dir - true if file is a directory
 * content - if file is not a directory, this string is written into the file
 */
struct file {
	char *path;
	bool dir;
	char *content;
};

/*
 * Description for creating a single mount:
 * mountpoint - path to create mount on (relative to dirname)
 * bind - id of bind source if any or -1
 * bind_root - root offset from bind source
 * fstype - needed for non-binds, always tmpfs
 * source - source for mounting
 * flags - array of sharing options or mount flags applied after
 *         mounting (ending with -1)
 * mounted - identifies implicitly propagated mounts
 * files - array of files we need to create on mount (ending with zeroed file)
 */
struct mountinfo {
	char *mountpoint;
	int bind;
	char *bind_root;
	char *fstype;
	char *source;
	int flags[3];
	bool mounted;
	struct file files[10];
};

/* clang-format off */
struct mountinfo mounts[] = {
	{"", -1, "", "tmpfs", "tmpfs-dirname", {MS_PRIVATE, -1}, false,
		{
			{"shared-bind-1", true},
			{"shared-bind-2", true},
			{"shared-bind-3", true},
			{"shared-bind-4", true},
			{"private-mnt", true},
			{"shared-mnt", true},
			{"slave-mnt", true},
			{"slave-shared-mnt", true},
			{"testfile", false, "TESTFILE"},
			{NULL}
		}
	},

	{"shared-bind-1", -1, "", "tmpfs", "tmpfs-shared-bind", {MS_SHARED, -1}, false,
		{
			{"prop-private", true},
			{"prop-shared", true},
			{"prop-slave", true},
			{"prop-slave-shared", true},
			{"prop-mount-flags", true},
			{NULL}
		}
	},
	{"shared-bind-2", 1, "", NULL, NULL, {-1}, false},
	{"shared-bind-3", 1, "", NULL, NULL, {-1}, false},
	{"shared-bind-4", 1, "", NULL, NULL, {-1}, false},

	{"private-mnt", -1, "", "tmpfs", "tmpfs-mnt", {MS_PRIVATE, -1}, false,
		{
			{"subdir", true},
			{NULL}
		}
	},
	{"shared-mnt", 5, "", NULL, NULL, {MS_SHARED, -1}, false},
	{"slave-mnt", 6, "", NULL, NULL, {MS_SLAVE, -1}, false},
	{"slave-shared-mnt", 7, "", NULL, NULL, {MS_SHARED, -1}, false},

	{"shared-bind-1/prop-private", 5, "subdir", NULL, NULL, {-1}, false},
	{"shared-bind-1/prop-shared", 6, "subdir", NULL, NULL, {-1}, false},
	{"shared-bind-1/prop-slave", 7, "subdir", NULL, NULL, {-1}, false},
	{"shared-bind-1/prop-slave-shared", 8, "subdir", NULL, NULL, {-1}, false},

	{"shared-bind-2/prop-private", -1, NULL, NULL, NULL, {MS_PRIVATE, -1}, true},
	{"shared-bind-2/prop-shared", -1, NULL, NULL, NULL, {MS_PRIVATE, -1}, true},
	{"shared-bind-2/prop-slave", -1, NULL, NULL, NULL, {MS_PRIVATE, -1}, true},
	{"shared-bind-2/prop-slave-shared", -1, NULL, NULL, NULL, {MS_PRIVATE, -1}, true},

	{"shared-bind-3/prop-private", -1, NULL, NULL, NULL, {MS_SLAVE, -1}, true},
	{"shared-bind-3/prop-shared", -1, NULL, NULL, NULL, {MS_SLAVE, -1}, true},
	{"shared-bind-3/prop-slave", -1, NULL, NULL, NULL, {MS_SLAVE, -1}, true},
	{"shared-bind-3/prop-slave-shared", -1, NULL, NULL, NULL, {MS_SLAVE, -1}, true},

	{"shared-bind-4/prop-private", -1, NULL, NULL, NULL, {MS_PRIVATE, MS_SHARED, -1}, true},
	{"shared-bind-4/prop-shared", -1, NULL, NULL, NULL, {MS_PRIVATE, MS_SHARED, -1}, true},
	{"shared-bind-4/prop-slave", -1, NULL, NULL, NULL, {MS_PRIVATE, MS_SHARED, -1}, true},
	{"shared-bind-4/prop-slave-shared", -1, NULL, NULL, NULL, {MS_PRIVATE, MS_SHARED, -1}, true},

	{"shared-bind-1/prop-mount-flags", 5, "subdir", NULL, NULL, {MS_RDONLY|MS_REMOUNT|MS_BIND, -1}, false},
	{"shared-bind-2/prop-mount-flags", -1, NULL, NULL, NULL, {MS_RDONLY|MS_REMOUNT|MS_BIND, -1}, true},
	{"shared-bind-3/prop-mount-flags", -1, NULL, NULL, NULL, {-1}, true},
	{"shared-bind-4/prop-mount-flags", -1, NULL, NULL, NULL, {-1}, true},
};
/* clang-format on */

static int fill_content(struct mountinfo *mi)
{
	struct file *file = &mi->files[0];
	char path[PATH_MAX];

	while (file->path != NULL) {
		snprintf(path, sizeof(path), "%s/%s/%s", dirname, mi->mountpoint, file->path);

		if (file->dir) {
			test_msg("Mkdir %s\n", path);
			if (mkdir(path, 0700)) {
				pr_perror("Failed to create dir %s", path);
				return -1;
			}
		} else {
			int fd, len = strlen(file->content);

			test_msg("Create file %s with content %s\n", path, file->content);
			fd = open(path, O_WRONLY | O_CREAT, 0777);
			if (fd < 0) {
				pr_perror("Failed to create file %s", path);
				return -1;
			}

			if (write(fd, file->content, len) != len) {
				pr_perror("Failed to write %s to file %s", file->content, path);
				close(fd);
				return -1;
			}
			close(fd);
		}

		file++;
	}

	return 0;
}

static int mount_one(struct mountinfo *mi)
{
	char source[PATH_MAX], target[PATH_MAX];
	int *flags = mi->flags, mflags = 0;
	char *fstype = NULL;

	test_msg("Mounting %s %d %s %s %d\n", mi->mountpoint, mi->bind, mi->fstype, mi->source, mi->mounted);

	snprintf(target, sizeof(target), "%s/%s", dirname, mi->mountpoint);

	if (mi->mounted)
		goto apply_flags;

	if (mi->bind != -1) {
		snprintf(source, sizeof(source), "%s/%s/%s", dirname, mounts[mi->bind].mountpoint, mi->bind_root);
		fstype = NULL;
		mflags = MS_BIND;
	} else {
		snprintf(source, sizeof(source), "%s", mi->source);
		fstype = mi->fstype;
	}

	if (mount(source, target, fstype, mflags, NULL)) {
		pr_perror("Failed to mount %s %s %s", source, target, fstype);
		return -1;
	}

	if (fill_content(mi))
		return -1;

apply_flags:
	while (flags[0] != -1) {
		test_msg("Making mount %s 0x%x\n", target, flags[0]);
		if (mount(NULL, target, NULL, flags[0], NULL)) {
			pr_perror("Failed to make mount %s 0x%x", target, flags[0]);
			return -1;
		}
		flags++;
	}

	return 0;
}

static int mount_loop(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mounts); i++) {
		if (mount_one(&mounts[i]))
			return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) && errno != EEXIST) {
		pr_perror("Failed to create %s", dirname);
		goto err;
	}

	if (mount_loop())
		goto err;

	test_daemon();
	test_waitsig();

	pass();
	ret = 0;
err:
	if (ret)
		fail();
	return ret;
}
