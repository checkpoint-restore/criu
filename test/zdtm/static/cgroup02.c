#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"
#include "mountinfo.h"

const char *test_doc = "Check that empty cgroups are preserved";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
static const char *subname = "oldroot";
static const char *cgname2 = "zdtmtst.defaultroot";

int mount_and_add(const char *controller, const char *prefix, const char *path)
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

	ssprintf(paux, "%s/%s", subdir, prefix);
	mkdir(paux, 0600);

	ssprintf(paux, "%s/%s/%s", subdir, prefix, path);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	ssprintf(paux, "%s/%s/%s/tasks", subdir, prefix, path);

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

bool test_exists(char *mountpoint, char *path)
{
	char paux[1024];
	struct stat st;

	test_msg("found cgroup at %s\n", mountpoint);

	ssprintf(paux, "%s/%s", mountpoint, path);
	if (stat(paux, &st)) {
		return false;
	}

	if (!S_ISDIR(st.st_mode)) {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct mountinfo_zdtm *mi;
	MNTNS_ZDTM(mntns);
	bool found_zdtmtstroot = false, found_newroot = false;
	char paux[1024];
	int ret = -1;
	int fd;

	test_init(argc, argv);

	if (mount_and_add(cgname, "prefix", subname))
		goto out;
	if (mount_and_add(cgname2, "prefix", subname)) {
		sprintf(paux, "%s/%s", dirname, cgname);
		umount(paux);
		rmdir(paux);
		goto out;
	}

	sprintf(paux, "%s/%s/prefix", dirname, cgname);
	fd = open(paux, O_DIRECTORY);
	if (fd < 0)
		goto out_umount;

	if (fchmod(fd, 0777) < 0) {
		fail("fchmod");
		goto out_umount;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		fail("fd didn't survive");
		goto out_umount;
	}

	if (mntns_parse_mountinfo(&mntns)) {
		fail("Can't parse mountinfo");
		goto out_umount;
	}

	list_for_each_entry(mi, &mntns.mountinfo_list, list) {
		if (strstr(mi->super_opts, cgname) && test_exists(mi->mountpoint, "prefix")) {
			found_zdtmtstroot = true;
		}

		if (strstr(mi->super_opts, cgname2) && test_exists(mi->mountpoint, "newroot")) {
			found_newroot = true;
		}
	}

	if (!found_zdtmtstroot) {
		fail("oldroot not rewritten to zdtmtstroot!");
		goto out_close;
	}

	if (!found_newroot) {
		fail("oldroot not rewritten to newroot!");
		goto out_close;
	}

	pass();
	ret = 0;

out_close:
	mntns_free_all(&mntns);
out_umount:
	sprintf(paux, "%s/%s", dirname, cgname);
	umount(paux);
	rmdir(paux);

	sprintf(paux, "%s/%s", dirname, cgname2);
	umount(paux);
	rmdir(paux);
out:
	return ret;
}
