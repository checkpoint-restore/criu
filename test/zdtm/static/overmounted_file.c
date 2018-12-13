#include <sys/mount.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "Check open file on overmounted mounts doesn't dump";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

#define DATA "Data"

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char overmounted[PATH_MAX];
	char buf[sizeof(DATA)];
	char file[PATH_MAX];
	int fd;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_fs", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(overmounted, "%s/overmounted", dirname);
	if (mkdir(overmounted, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("overmounted", overmounted, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(file, "%s/file", overmounted);
	fd = open(file, O_CREAT|O_WRONLY, 0600);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	if (write(fd, DATA, sizeof(DATA)) != sizeof(DATA)) {
		pr_perror("write");
		return 1;
	}
	close(fd);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	if (mount(overmounted, overmounted, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (read(fd, buf, sizeof(DATA)) != sizeof(DATA)) {
		fail("Can't read from file");
		return 1;
	}

	if (strcmp(buf, DATA)) {
		fail("Wrong data in a file");
		return 1;
	}

	close(fd);

	if (umount(overmounted)) {
		pr_perror("umount");
		return 1;
	}

	if (umount(overmounted)) {
		pr_perror("umount");
		return 1;
	}

	if (umount(dirname)) {
		pr_perror("umount");
		return 1;
	}

	pass();

	return 0;
}
