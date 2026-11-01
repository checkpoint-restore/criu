#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check --cgroup-root for a task in the root cgroup and its child in a nested one";
const char *test_author = "Kir Kolyshkin <kolyshkin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);

/*
 * The task stays in the root of this hierarchy, which is then dumped as a
 * cgroup with an empty name, and the child is moved into a nested cgroup.
 * On restore, the hierarchy is relocated by --cgroup-root, see .desc.
 */
static const char *cgname = "zdtmtst";
static const char *newroot = "/newroot";
/*
 * The task is moved out of the root of this hierarchy, so that its cgroup
 * set differs from the one of CRIU, which would not be dumped otherwise.
 */
static const char *cgname2 = "zdtmtst.defaultroot";
static const char *subname = "cgroup_newroot";

static int move_to_cgroup(const char *controller, const char *path, pid_t pid)
{
	char mnt[PATH_MAX], aux[PATH_MAX];
	int fd, ret = -1;

	ssprintf(mnt, "%s/%s", dirname, controller);
	if (mkdir(mnt, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't create %s", mnt);
		return -1;
	}

	ssprintf(aux, "none,name=%s", controller);
	if (mount("none", mnt, "cgroup", 0, aux)) {
		pr_perror("Can't mount the %s hierarchy", controller);
		goto out_rmdir;
	}

	ssprintf(aux, "%s/%s", mnt, path);
	if (mkdir(aux, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't create %s", aux);
		goto out_umount;
	}

	ssprintf(aux, "%s/%s/cgroup.procs", mnt, path);
	fd = open(aux, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", aux);
		goto out_umount;
	}

	if (dprintf(fd, "%d", pid) < 0)
		pr_perror("Can't move %d into %s", pid, aux);
	else
		ret = 0;
	close(fd);

out_umount:
	umount(mnt);
out_rmdir:
	rmdir(mnt);
	return ret;
}

/* Get the cgroup of a task in a given hierarchy. */
static int get_cgroup(pid_t pid, const char *controller, char *path, size_t size)
{
	char aux[PATH_MAX], line[PATH_MAX];
	int ret = -1;
	FILE *f;

	ssprintf(aux, "/proc/%d/cgroup", pid);
	f = fopen(aux, "r");
	if (!f) {
		pr_perror("Can't open %s", aux);
		return -1;
	}

	ssprintf(aux, ":name=%s:", controller);
	while (fgets(line, sizeof(line), f)) {
		char *s = strstr(line, aux);

		if (!s)
			continue;
		s += strlen(aux);
		s[strcspn(s, "\n")] = '\0';
		if (snprintf(path, size, "%s", s) < size)
			ret = 0;
		break;
	}
	fclose(f);

	if (ret)
		pr_err("No %s cgroup found for %d\n", controller, pid);
	return ret;
}

static int check_cgroup(pid_t pid, const char *controller, const char *expected)
{
	char path[PATH_MAX];

	if (get_cgroup(pid, controller, path, sizeof(path)))
		return -1;

	if (strcmp(path, expected)) {
		fail("%d is in %s, expected %s", pid, path, expected);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char child_path[PATH_MAX];
	int ret = 1;
	pid_t pid;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't create %s", dirname);
		return 1;
	}

	if (move_to_cgroup(cgname2, subname, getpid()))
		goto out;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		while (1)
			pause();
	}

	if (move_to_cgroup(cgname, subname, pid))
		goto out_kill;

	if (check_cgroup(getpid(), cgname, "/"))
		goto out_kill;

	test_daemon();
	test_waitsig();

	ssprintf(child_path, "%s/%s", newroot, subname);
	if (check_cgroup(getpid(), cgname, newroot) || check_cgroup(pid, cgname, child_path))
		goto out_kill;

	pass();
	ret = 0;

out_kill:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
out:
	rmdir(dirname);
	return ret;
}
