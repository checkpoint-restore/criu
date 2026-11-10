#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check an inotify watch on a cgroup2 directory";
const char *test_author = "Denis V. Lunev <den@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define CGNAME	  "inotify_cgroup2"
#define CHILDNAME "child"

int main(int argc, char **argv)
{
	char cg[PATH_MAX], child[PATH_MAX];
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	struct inotify_event *ev = (struct inotify_event *)buf;
	int fd, len, ret = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) && errno != EEXIST) {
		pr_perror("Can't create %s", dirname);
		return 1;
	}

	if (mount("cgroup2", dirname, "cgroup2", 0, NULL)) {
		pr_perror("Can't mount cgroup2 on %s", dirname);
		goto out_rmdir;
	}

	snprintf(cg, sizeof(cg), "%s/" CGNAME, dirname);
	snprintf(child, sizeof(child), "%s/" CGNAME "/" CHILDNAME, dirname);
	if (mkdir(cg, 0700)) {
		pr_perror("Can't create %s", cg);
		goto out_umount;
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init1");
		goto out_cg;
	}

	if (inotify_add_watch(fd, cg, IN_CREATE) < 0) {
		pr_perror("Can't watch %s", cg);
		goto out_cg;
	}

	test_daemon();
	test_waitsig();

	if (mkdir(child, 0700)) {
		pr_perror("Can't create %s", child);
		goto out_cg;
	}

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		fail("No event for %s", child);
		goto out_child;
	}

	if (len != sizeof(*ev) + ev->len || !(ev->mask & IN_CREATE) || strcmp(ev->name, CHILDNAME)) {
		fail("Unexpected event mask 0x%x name %s", ev->mask, ev->len ? ev->name : "");
		goto out_child;
	}

	pass();
	ret = 0;
out_child:
	rmdir(child);
out_cg:
	rmdir(cg);
out_umount:
	umount(dirname);
out_rmdir:
	rmdir(dirname);
	return ret;
}
