#define _GNU_SOURCE
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

		/* skip heirarchy no. */
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

static int unshare_cgns_and_wait(void *arg)
{
	int sk = *((int*)arg), ret = -1;
	char c;
	char buf[20];

	if (unshare(CLONE_NEWCGROUP) < 0) {
		pr_perror("unshare");
		goto out;
	}

	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto out;
	}


	if (read(sk, &c, 1) != 1) {
		pr_perror("read %d", ret);
		goto out;
	}

	sprintf(buf, "name=%s", cgname);

	if (!pid_in_cgroup(getpid(), buf, "/")) {
		pr_err("subtask not in right cg!\n");
		goto out;
	}

	ret = 0;
out:
	close(sk);
	return ret;
}

int main(int argc, char **argv)
{
	int ret = -1, sk_pair[2], sk, status;
	char path[PATH_MAX], c;
	pid_t pid;

	test_init(argc, argv);

	if (mount_and_add(cgname, "test") < 0)
		return -1;

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		pr_perror("socketpair");
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork failed");
		goto out;
	}

	if (pid == 0) {
		close(sk_pair[0]);
		if (unshare_cgns_and_wait(sk_pair+1))
			exit(1);
		exit(0);
	}

	close(sk_pair[1]);
	sk = sk_pair[0];

	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto out;
	}

	test_daemon();
	test_waitsig();

	sprintf(path, "name=%s", cgname);

	/* first check that the task is in zdtmtst:/test */
	if (!pid_in_cgroup(pid, path, "/test")) {
		fail("pid not in cgroup /test");
		goto out;
	}

	/* now have the task check that it is in / */
	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto out;
	}

	if (pid != waitpid(pid, &status, 0)) {
		pr_perror("waitpid");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("exit status %s\n", status);
		goto out;
	}

	pass();
	ret = 0;
out:
	sprintf(path, "%s/%s/test", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return ret;
}
