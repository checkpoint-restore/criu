#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <limits.h>
#include "zdtmtst.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

const char *test_doc = "Check that cgroup NS is restored in --manage-cgroups=ignore mode.";
const char *test_author = "Kir Kolyshkin <kolyshkin@gmail.com>";

/* we need dirname before test_init() here */
char *dirname = "cgroupns_ignore.test";
static const char *cgname = "zdtmtst_ignore";

static int mount_and_add(const char *controller, const char *path)
{
	char aux[1024], paux[1024], subdir[1024];
	int cgfd, l;

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	ssprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		pr_perror("Can't make dir");
		return -1;
	}

	ssprintf(aux, "none,name=%s", controller);
	if (mount("none", subdir, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto err_rd;
	}

	ssprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	l = ssprintf(aux, "%d", getpid());
	ssprintf(paux, "%s/%s/tasks", subdir, path);

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
	umount(subdir);
err_rd:
	rmdir(subdir);
	rmdir(dirname);
	return -1;
}

static int get_cgns_id(pid_t pid, ino_t *id)
{
	char path[PATH_MAX];
	struct stat st;

	ssprintf(path, "/proc/%d/ns/cgroup", pid);
	if (stat(path, &st) < 0) {
		pr_perror("Can't stat %s", path);
		return -1;
	}

	*id = st.st_ino;
	return 0;
}

int main(int argc, char **argv)
{
	ino_t init_cgns, self_cgns;
	char path[PATH_MAX];
	int ret = -1;

	/*
	 * The cgroup namespace has to be unshared while being in a
	 * non-root cgroup, otherwise there is no cgns prefix to dump.
	 */
	if (mount_and_add(cgname, "test") < 0)
		return -1;

	if (unshare(CLONE_NEWCGROUP) < 0) {
		pr_perror("Can't unshare cgns");
		goto out;
	}

	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	/*
	 * In the ignore mode CRIU does not move the restored tasks into
	 * any cgroup, so the only thing to check is that the tasks still
	 * live in a cgroup namespace of their own rather than in the one
	 * inherited from CRIU.
	 */
	if (get_cgns_id(1, &init_cgns) < 0 || get_cgns_id(getpid(), &self_cgns) < 0)
		goto out;

	if (init_cgns == self_cgns) {
		fail("cgroup namespace is not restored");
		goto out;
	}

	ret = 0;
	pass();

out:
	ssprintf(path, "%s/%s/test", dirname, cgname);
	rmdir(path);
	ssprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return ret;
}
