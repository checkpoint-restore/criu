#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that global cgroup settings (+perms) are restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";

int mount_and_add(const char *controller, const char *path)
{
	char aux[1024], paux[1024], subdir[1024];
	int cgfd, l;

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(aux, "none,name=%s", controller);
	if (mount("none", subdir, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto err_rd;
	}

	sprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	sprintf(paux, "%s/%s/tasks", subdir, path);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks");
		goto err_rs;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		pr_perror("Can't move self to subcg");
		goto err_rs;
	}

	return 0;
err_rs:
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

int chownmod(char *path, int flags)
{
	int fd, ret = -1;

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("can't open %s", path);
		return -1;
	}

	if (fchown(fd, 1000, 1000) < 0) {
		pr_perror("can't chown %s", path);
		goto out;
	}

	if (fchmod(fd, 0777) < 0) {
		pr_perror("can't chmod %s", path);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

int checkperms(char *path)
{
	struct stat sb;

	if (stat(path, &sb) < 0) {
		pr_perror("can't stat %s", path);
		return -1;
	}

	if ((sb.st_mode & 0777) != 0777) {
		fail("mode for %s doesn't match (%o)\n", path, sb.st_mode);
		return -1;
	}

	if (sb.st_uid != 1000) {
		fail("uid for %s doesn't match (%d)\n", path, sb.st_uid);
		return -1;
	}

	if (sb.st_gid != 1000) {
		fail("gid for %s doesn't match (%d)\n", path, sb.st_gid);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = -1;
	char path[PATH_MAX];

	test_init(argc, argv);

	if (mount_and_add(cgname, "test") < 0)
		return -1;

	sprintf(path, "%s/%s/test", dirname, cgname);
	if (chownmod(path, O_DIRECTORY) < 0)
		goto out_umount;

	sprintf(path, "%s/%s/test/notify_on_release", dirname, cgname);
	if (chownmod(path, O_RDWR) < 0)
		goto out_umount;


	sprintf(path, "%s/%s/test/cgroup.procs", dirname, cgname);
	if (chownmod(path, O_RDWR) < 0)
		goto out_umount;

	test_daemon();
	test_waitsig();

	sprintf(path, "%s/%s/test", dirname, cgname);
	if (checkperms(path) < 0)
		goto out_umount;

	sprintf(path, "%s/%s/test/notify_on_release", dirname, cgname);
	if (checkperms(path) < 0)
		goto out_umount;

	sprintf(path, "%s/%s/test/cgroup.procs", dirname, cgname);
	if (checkperms(path) < 0)
		goto out_umount;

	pass();
	ret = 0;

out_umount:
	sprintf(path, "%s/%s/test", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return ret;
}
