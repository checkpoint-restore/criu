#include <fcntl.h>
#include <linux/limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of fds to files, directories on unmounted mounts";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define MOUNT_POINT "mnt"
#define SUBDIR	    "mnt/subdir"
#define FILE	    "mnt/file"

#define BUFLEN 1000

static int get_subdir_fd(void)
{
	int fd = -1;
	if (mkdir(SUBDIR, 0700)) {
		pr_perror("mkdir %s", SUBDIR);
		return -1;
	}
	fd = open(SUBDIR, O_DIRECTORY);
	if (fd < 0) {
		pr_perror("open %s", SUBDIR);
		return -1;
	}
	return fd;
}

static int get_file_fd(uint32_t *crc)
{
	uint8_t buf[BUFLEN];
	int fd = -1;

	fd = open(FILE, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		pr_perror("open %s", FILE);
		return -1;
	}
	datagen(buf, BUFLEN, crc);
	if (write(fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("write %s", FILE);
		close(fd);
		return -1;
	}
	return fd;
}

int main(int argc, char *argv[])
{
	int subdir_fd = -1, file_fd = -1, ret = 1;
	uint32_t crc = ~0;
	uint8_t buf[BUFLEN];
	struct stat st;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		return 1;
	}

	if (chdir(dirname)) {
		pr_perror("chdir %s", dirname);
		return 1;
	}

	if (mkdir(MOUNT_POINT, 0700)) {
		pr_perror("mkdir %s", MOUNT_POINT);
		return 1;
	}

	if (mount("none", MOUNT_POINT, "tmpfs", 0, NULL)) {
		pr_perror("mount %s", MOUNT_POINT);
		return 1;
	}

	subdir_fd = get_subdir_fd();
	if (subdir_fd < 0)
		goto err;

	file_fd = get_file_fd(&crc);
	if (file_fd < 0)
		goto err;

	if (umount2(MOUNT_POINT, MNT_DETACH)) {
		pr_perror("umount2 %s", MOUNT_POINT);
		goto err;
	}

	test_daemon();
	test_waitsig();

	/* Should still be able to read from the fd */
	if (lseek(file_fd, 0, SEEK_SET)) {
		pr_perror("lseek %s", FILE);
		goto out;
	}

	if (read(file_fd, buf, BUFLEN) != BUFLEN) {
		pr_perror("read %s", FILE);
		ret = 1;
		goto out;
	}

	crc = ~0;
	if (datachk(buf, BUFLEN, &crc)) {
		fail("Data mismatch");
		goto out;
	}

	if (fstat(subdir_fd, &st)) {
		fail("could not stat dir fd");
		goto out;
	}

	if (S_ISDIR(st.st_mode)) {
		ret = 0;
		pass();
		goto out;
	} else {
		fail("dir fd does not point to a dir");
		goto out;
	}
err:
	umount(MOUNT_POINT);
out:
	chdir("..");
	if (subdir_fd > 0)
		close(subdir_fd);
	if (file_fd > 0)
		close(file_fd);
	return ret;
}
