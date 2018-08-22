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

const char *test_doc	= "Check that stray cgroups are c/r'd correctly";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";

static int mount_ctrl(const char *controller)
{
	char aux[1024], subdir[1024];

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

	return 0;
err_rd:
	rmdir(dirname);
	return -1;
}

static int add_to_cg(const char *controller, const char *path)
{
	char aux[1024], paux[1024], subdir[1024];
	int cgfd, l;

	sprintf(subdir, "%s/%s", dirname, controller);
	ssprintf(paux, "%s/%s", subdir, path);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	ssprintf(paux, "%s/%s/tasks", subdir, path);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks %s", paux);
		return -1;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		pr_perror("Can't move self to subcg %s", path);
		return -1;
	}

	return 0;
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

test_msg("comparing %s and %s\n", controller, pid_controller);
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
	int ret = -1, sk_pair[2], sk, status;
	char path[PATH_MAX], c;
	pid_t pid = 0;

	test_init(argc, argv);

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		pr_perror("socketpair");
		return -1;
	}

	if (mount_ctrl(cgname) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		goto out_umount;
	}

	if (pid == 0) {
		close(sk_pair[0]);
		sk = sk_pair[1];

		if (add_to_cg(cgname, "foo"))
			exit(1);

		if (write(sk, &c, 1) != 1) {
			pr_perror("write");
			exit(1);
		}

		if (read(sk, &c, 1) != 1) {
			pr_perror("read %d", ret);
			exit(1);
		}

		sprintf(path, "name=%s", cgname);
		if (!pid_in_cgroup(getpid(), path, "/foo"))
			exit(1);
		exit(0);
	}

	close(sk_pair[1]);
	sk = sk_pair[0];

	if (add_to_cg(cgname, "bar"))
		goto out_kill;

	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto out_kill;
	}

	sprintf(path, "name=%s", cgname);
	if (!pid_in_cgroup(getpid(), path, "/bar")) {
		fail("parent not in cgroup /bar");
		goto out_kill;
	}

	if (pid != waitpid(pid, &status, 0)) {
		pr_perror("waitpid");
		goto out_umount;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("exit status %d\n", status);
		goto out_umount;
	}

	pass();
	ret = 0;

out_kill:
	if (pid > 0)
		kill(pid, SIGKILL);

out_umount:
	sprintf(path, "%s/%s/foo", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/%s/test", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return ret;
}
