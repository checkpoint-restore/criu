#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that xattrs on cgroup are detected";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtstxattr";
static const char *subname = "subcg";

#define ZDTM_TST_XATTR "trusted.zdtmtest"
#define ZDTM_TST_XATTR_VAL "zdtmtest"
#define ZDTM_TST_XATTR_SIZE sizeof(ZDTM_TST_XATTR_VAL)

int main(int argc, char **argv)
{
	int tasks_fd, l, ret = 1;
	char aux[1024], tasks[1024], subdir[1024];

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		goto out;
	}

	sprintf(aux, "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto out_rd;
	}

	sprintf(subdir, "%s/%s", dirname, subname);
	if (mkdir(subdir, 0600)) {
		pr_perror("Can't mkdir subcg");
		goto out_um;
	}

	l = sprintf(aux, "%d", getpid());
	sprintf(tasks, "%s/%s/tasks", dirname, subname);

	tasks_fd = open(tasks, O_WRONLY);
	if (tasks_fd < 0) {
		pr_perror("Can't open tasks");
		goto out_rs;
	}

	l = write(tasks_fd, aux, l);
	close(tasks_fd);

	if (l < 0) {
		pr_perror("Can't move self to subcg");
		goto out_rs;
	}

	if (setxattr(tasks, ZDTM_TST_XATTR, ZDTM_TST_XATTR_VAL, ZDTM_TST_XATTR_SIZE, 0)) {
		pr_perror("Can't set xattr");
		goto out_rs;
	}

	test_daemon();
	test_waitsig();

	if (removexattr(tasks, ZDTM_TST_XATTR)) {
		pr_perror("Can't remove xattr");
		goto out_rs;
	}

	pass();
	ret = 0;
out_rs:
	rmdir(subdir);
out_um:
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return ret;
}
