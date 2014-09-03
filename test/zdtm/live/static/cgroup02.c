#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that empty cgroups are preserved";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
static const char *subname = "oldroot";
static const char *cgname2 = "zdtmtst.defaultroot";

int mount_and_add(const char *controller, const char *path)
{
	char aux[1024], paux[1024], subdir[1024];
	int cgfd, l;

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		err("Can't make dir");
		return -1;
	}

	sprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		err("Can't make dir");
		return -1;
	}

	sprintf(aux, "none,name=%s", controller);
	if (mount("none", subdir, "cgroup", 0, aux)) {
		err("Can't mount cgroups");
		goto err_rd;
	}

	sprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	sprintf(paux, "%s/%s/tasks", subdir, path);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		err("Can't open tasks");
		goto err_rs;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		err("Can't move self to subcg");
		goto err_rs;
	}

	return 0;
err_rs:
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

bool test_exists(char *mountinfo_line, char *path)
{
	char aux[1024], paux[1024];
	struct stat st;

	sscanf(mountinfo_line, "%*d %*d %*d:%*d %*s %s", aux);
	test_msg("found cgroup at %s\n", aux);

	sprintf(paux, "%s/%s", aux, path);
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
	FILE *cgf;
	bool found_zdtmtstroot = false, found_newroot = false;
	char paux[1024];
	int ret = -1;

	test_init(argc, argv);

	if (mount_and_add(cgname, subname))
		goto out;
	if (mount_and_add(cgname2, subname)) {
		sprintf(paux, "%s/%s", dirname, cgname);
		umount(paux);
		rmdir(paux);
		goto out;
	}

	test_daemon();
	test_waitsig();

	cgf = fopen("/proc/self/mountinfo", "r");
	if (cgf == NULL) {
		fail("No mountinfo file");
		goto out_umount;
	}

	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strstr(paux, cgname);
		if (s && test_exists(paux, "zdtmtstroot")) {
			found_zdtmtstroot = true;
		}

		s = strstr(paux, cgname2);
		if (s && test_exists(paux, "newroot")) {
			found_newroot = true;
		}
	}

	if (!found_zdtmtstroot) {
		fail("oldroot not rewritten to zdtmtstroot!\n");
		goto out_close;
	}

	if (!found_newroot) {
		fail("oldroot not rewritten to newroot!\n");
		goto out_close;
	}

	pass();
	ret = 0;


out_close:
	fclose(cgf);
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
