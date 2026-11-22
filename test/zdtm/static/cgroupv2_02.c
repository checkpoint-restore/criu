#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check that cgroup.subtree_control is restored in an existing cgroup-v2 directory with controllers already enabled";
const char *test_author = "Hitesh Chandra <hiteshchandra2703@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup-v2 directory name", 1);
const char *cgname = "subcg02";

int main(int argc, char **argv)
{
	char path[1024], aux[1024];
	int ret = -1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	if (mount("cgroup2", dirname, "cgroup2", 0, NULL)) {
		pr_perror("Can't mount cgroup-v2");
		return -1;
	}

	sprintf(path, "%s/%s", dirname, cgname);
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		goto out;
	}

	/* Make cpuset controllers available in children directory */
	sprintf(path, "%s/%s", dirname, "cgroup.subtree_control");
	sprintf(aux, "%s", "+cpuset");
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "cgroup.subtree_control");
	sprintf(aux, "%s", "+cpuset");
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "cgroup.procs");
	sprintf(aux, "%d", getpid());
	if (write_value(path, aux))
		goto out;

	test_daemon();
	test_waitsig();

	sprintf(path, "%s/%s/%s", dirname, cgname, "cgroup.subtree_control");
	if (read_value(path, aux, sizeof(aux)))
		goto out;

	if (strcmp(aux, "cpuset\n")) {
		fail("cgroup.subtree_control mismatches");
		goto out;
	}

	pass();

	ret = 0;

out:
	sprintf(path, "%s", dirname);
	umount(path);
	return ret;
}
