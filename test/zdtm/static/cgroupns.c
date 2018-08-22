#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <limits.h>
#include "zdtmtst.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif

const char *test_doc	= "Check that cgroup NS is correctly handled.";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

/* we need dirname before test_init() here */
char *dirname = "cgroupns.test";
static const char *cgname = "zdtmtst";

int mount_and_add(const char *controller, const char *path)
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
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

static bool pid_in_cgroup(pid_t pid, const char *controller, const char *path) {
	char buf[2048];
	FILE *f;
	bool ret = false;

	sprintf(buf, "/proc/%d/cgroup", pid);
	f = fopen(buf, "r");
	if (!f) {
		pr_perror("fopen");
		return false;
	}

	while (NULL != fgets(buf, sizeof(buf), f)) {
		char *pos, *pid_controller, *pid_path;

		/* chop off trailing \n */
		buf[strlen(buf)-1] = '\0';

		/* skip hierarchy no. */
		pos = strstr(buf, ":");
		if (!pos) {
			pr_err("invalid /proc/pid/cgroups file");
			goto out;
		}
		pos++;
		pid_controller = pos;

		pos = strstr(pos, ":");
		if (!pos) {
			pr_err("invalid /proc/pid/cgroups file");
			goto out;
		}

		*pos = '\0';
		pos++;
		pid_path = pos;

		if (strcmp(controller, pid_controller))
			continue;

		if (strcmp(path, pid_path))
			pr_err("task not in right cg for controller %s expected %s, got %s\n", controller, path, pid_path);
		else
			ret = true;

		goto out;
	}

out:
	fclose(f);
	return ret;
}

int main(int argc, char **argv)
{
	int ret = -1, fd, status;
	char path[PATH_MAX];
	pid_t pid;

	if (!getenv("ZDTM_NEWNS")) {
		if (mount_and_add(cgname, "test") < 0)
			return -1;

		if (unshare(CLONE_NEWCGROUP) < 0) {
			pr_perror("unshare");
			goto out;
		}
	}

	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	sprintf(path, "name=%s", cgname);

	/* first check that the task is in zdtmtst:/ */
	if (!pid_in_cgroup(getpid(), path, "/")) {
		fail("pid not in cgroup /");
		goto out;
	}

	/* now check that the task is in the right place in a ns by setnsing to
	 * someone else's ns and looking there.
	 */
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		goto out;
	}

	if (pid == 0) {
		sprintf(path, "/proc/%d/ns/cgroup", 1);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			pr_perror("open");
			exit(1);
		}

		ret = setns(fd, CLONE_NEWCGROUP);
		close(fd);
		if (ret < 0) {
			pr_perror("setns");
			exit(1);
		}

		sprintf(path, "name=%s", cgname);
		if (!pid_in_cgroup(getppid(), path, "/test")) {
			fail("pid not in cgroup %s", path);
			exit(1);
		}

		exit(0);
	}

	if (pid != waitpid(pid, &status, 0)) {
		pr_err("wrong pid");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("got bad exit status %d\n", status);
		goto out;
	}

	ret = 0;
	pass();

out:
	sprintf(path, "%s/%s/test", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return ret;
}
