#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check that open file on unmounted mount is restored correctly";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_FILE "detached-mount-file"

int main(int argc, char *argv[])
{
	char path[PATH_MAX];
	 /* opened to a file on the detached mount point */
	int fd;
	char *data = "detached_mount.data";
	size_t len = strlen(data);
	char buf[len + 1];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		return 1;
	}

	/* create a mount point at dirname */
	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount %s", dirname);
		return 1;
	}

	ssprintf(path, "%s/%s", dirname, TEST_FILE);
	fd = open(path, O_CREAT | O_RDWR);
	if (fd < 0) {
		pr_perror("open %s", path);
		return 1;
	}

	if (write(fd, data, len) != len) {
		pr_perror("write %s", path);
		goto err;
	}

	/* detach the mount lazily */
	if (umount2(dirname, MNT_DETACH)) {
		pr_perror("umount2 %s", dirname);
		goto err;
	}

	test_daemon();
	test_waitsig();

	/* Should still be able to read from the fd */
	if (lseek(fd, 0, SEEK_SET)) {
		pr_perror("lseek %s", path);
		goto err;
	}

	if (read(fd, buf, len) != len) {
		pr_perror("read %s", path);
		goto err;
	}

	buf[len] = 0;
	/* Should contain the same data */
	if (strncmp(data, buf, len) != 0)
		fail();
	else
		pass();

	close(fd);
	return 0;
err:
	close(fd);
	return 1;
}
