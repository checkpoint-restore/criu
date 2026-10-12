#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check mount restore through the userns-first mount broker";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

#define TEST_DIR  "rootless_mntns_broker.test"
#define TEST_FILE TEST_DIR "/payload"
#define TEST_DATA "mntns broker payload\n"

static int write_payload(void)
{
	int fd, ret = -1;
	ssize_t len = strlen(TEST_DATA);

	fd = open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("open %s", TEST_FILE);
		return -1;
	}

	if (write(fd, TEST_DATA, len) != len) {
		pr_perror("write %s", TEST_FILE);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int check_payload(void)
{
	char buf[sizeof(TEST_DATA)] = {};
	int fd, ret = -1;
	ssize_t len = strlen(TEST_DATA), n;

	fd = open(TEST_FILE, O_RDONLY);
	if (fd < 0) {
		pr_perror("open %s", TEST_FILE);
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		pr_perror("read %s", TEST_FILE);
		goto out;
	}

	if (n != len || strcmp(buf, TEST_DATA)) {
		fail("payload mismatch: %s", buf);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int check_separate_mount(void)
{
	struct stat parent, mounted;

	if (stat(".", &parent)) {
		pr_perror("stat .");
		return -1;
	}

	if (stat(TEST_DIR, &mounted)) {
		pr_perror("stat %s", TEST_DIR);
		return -1;
	}

	if (parent.st_dev == mounted.st_dev) {
		fail("%s is not a separate mount", TEST_DIR);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (mkdir(TEST_DIR, 0755) && errno != EEXIST) {
		pr_perror("mkdir %s", TEST_DIR);
		return 1;
	}

	if (mount("none", TEST_DIR, "tmpfs", 0, "mode=0755")) {
		pr_perror("mount %s", TEST_DIR);
		goto out_rmdir;
	}

	if (write_payload())
		goto out_umount;

	if (check_separate_mount())
		goto out_umount;

	test_daemon();
	test_waitsig();

	if (check_separate_mount())
		goto out_umount;

	if (check_payload())
		goto out_umount;

	pass();
	ret = 0;

out_umount:
	if (umount(TEST_DIR)) {
		pr_perror("umount %s", TEST_DIR);
		ret = 1;
	}
out_rmdir:
	if (rmdir(TEST_DIR)) {
		pr_perror("rmdir %s", TEST_DIR);
		ret = 1;
	}

	return ret;
}
