
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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

const char *test_doc = "Check that some cgroups properties in kernel controllers are preserved";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";

int write_value(const char *path, const char *value)
{
	int fd, l;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("open %s", path);
		return -1;
	}

	l = write(fd, value, strlen(value));
	close(fd);
	if (l < 0) {
		pr_perror("failed to write %s to %s", value, path);
		return -1;
	}

	return 0;
}

int mount_and_add(const char *controller, const char *path, const char *prop, const char *value)
{
	char aux[1024], paux[1024], subdir[1024];

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		pr_perror("Can't make dir");
		return -1;
	}

	if (mount("none", subdir, "cgroup", 0, controller)) {
		pr_perror("Can't mount cgroups");
		goto err_rd;
	}

	ssprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	ssprintf(paux, "%s/%s/%s", subdir, path, prop);
	if (write_value(paux, value) < 0)
		goto err_rs;

	sprintf(aux, "%d", getpid());
	ssprintf(paux, "%s/%s/tasks", subdir, path);
	if (write_value(paux, aux) < 0)
		goto err_rs;

	ssprintf(paux, "%s/%s/special_prop_check", subdir, path);
	mkdir(paux, 0600);

	return 0;
err_rs:
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

bool checkval(char *path, char *val)
{
	char buf[1024];
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("open %s", path);
		return false;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0) {
		pr_perror("read");
		return false;
	}
	buf[n] = 0;

	if (strcmp(val, buf)) {
		pr_err("got %s expected %s\n", buf, val);
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	int ret = -1, i;
	char buf[1024], path[PATH_MAX];
	struct stat sb;

	char *dev_allow[] = {
		"c *:* m",   "b *:* m",	  "c 1:3 rwm", "c 1:5 rwm",   "c 1:7 rwm",    "c 5:0 rwm",
		"c 5:2 rwm", "c 1:8 rwm", "c 1:9 rwm", "c 136:* rwm", "c 10:229 rwm",
	};

	test_init(argc, argv);

	if (mount_and_add("devices", cgname, "devices.deny", "a") < 0)
		goto out;

	/* need to allow /dev/null for restore */
	sprintf(path, "%s/devices/%s/devices.allow", dirname, cgname);
	for (i = 0; i < ARRAY_SIZE(dev_allow); i++) {
		if (write_value(path, dev_allow[i]) < 0)
			goto out;
	}

	if (mount_and_add("memory", cgname, "memory.limit_in_bytes", "268435456") < 0)
		goto out;

	test_daemon();
	test_waitsig();

	buf[0] = 0;
	for (i = 0; i < ARRAY_SIZE(dev_allow); i++) {
		strcat(buf, dev_allow[i]);
		strcat(buf, "\n");
	}

	sprintf(path, "%s/devices/%s/devices.list", dirname, cgname);
	if (!checkval(path, buf)) {
		fail();
		goto out;
	}

	sprintf(path, "%s/memory/%s/memory.limit_in_bytes", dirname, cgname);
	if (!checkval(path, "268435456\n")) {
		fail();
		goto out;
	}

	sprintf(path, "%s/devices/%s/special_prop_check", dirname, cgname);
	if (stat(path, &sb) < 0) {
		fail("special_prop_check doesn't exist?");
		goto out;
	}

	if (!S_ISDIR(sb.st_mode)) {
		fail("special_prop_check not a directory?");
		goto out;
	}

	pass();
	ret = 0;
out:
	sprintf(path, "%s/devices/%s/special_prop_check", dirname, cgname);
	rmdir(path);

	sprintf(path, "%s/devices/%s", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/devices", dirname);
	umount(path);

	sprintf(path, "%s/memory/%s", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/memory", dirname);
	umount(path);

	return ret;
}
