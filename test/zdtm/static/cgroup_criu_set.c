#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include "zdtmtst.h"

const char *test_doc = "Check that tasks and threads in the cgroup criu is in are restored "
		       "when their parent (or main thread) is in another cgroup";
const char *test_author = "Kir Kolyshkin <kolyshkin@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
#define SUBNAME "subcg_criu_set"

/* The cgroup the test is started in, which is the one criu is in, too. */
static char orig[256];

/* Get the cgroup of the calling thread in the test hierarchy. */
static int get_cgroup(char *buf, size_t size)
{
	char line[512], name[64];
	FILE *f;
	int ret = -1;

	f = fopen("/proc/thread-self/cgroup", "r");
	if (!f) {
		pr_perror("Can't open /proc/thread-self/cgroup");
		return -1;
	}

	snprintf(name, sizeof(name), ":name=%s:", cgname);
	while (fgets(line, sizeof(line), f)) {
		char *s = strstr(line, name);

		if (!s)
			continue;
		s += strlen(name);
		s[strcspn(s, "\n")] = '\0';
		snprintf(buf, size, "%s", s);
		ret = 0;
		break;
	}

	fclose(f);
	if (ret)
		pr_err("No %s cgroup found\n", cgname);
	return ret;
}

/* Move the calling thread (or the whole process) into the cgroup. */
static int cg_move(const char *name, const char *file)
{
	char path[512];
	int fd, ret;

	snprintf(path, sizeof(path), "%s/%s/%s", dirname, name, file);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}
	ret = write(fd, "0", 2);
	close(fd);
	if (ret < 0) {
		pr_perror("Can't write to %s", path);
		return -1;
	}

	return 0;
}

static int cg_check(const char *name, const char *who)
{
	char cg[256];

	if (get_cgroup(cg, sizeof(cg)))
		return -1;
	if (strcmp(cg, name)) {
		fail("The %s is in %s, expected %s", who, cg, name);
		return -1;
	}

	return 0;
}

static int thread_pipe[2], thread_restored[2];

static void *thread_fn(void *arg)
{
	int status;

	/* Back into the cgroup criu is in, away from the main thread. */
	status = cg_move(orig, "tasks");
	write(thread_pipe[1], &status, sizeof(status));
	if (status)
		return NULL;

	read(thread_restored[0], &status, sizeof(status));
	status = cg_check(orig, "thread");
	write(thread_pipe[1], &status, sizeof(status));

	return NULL;
}

int main(int argc, char **argv)
{
	int child_pipe[2], child_restored[2], status, ret = 1;
	char sub[sizeof(orig) + sizeof(SUBNAME) + 1], aux[1024];
	pthread_t thread;
	pid_t pid;

	test_init(argc, argv);

	if (pipe(child_pipe) || pipe(child_restored) || pipe(thread_pipe) || pipe(thread_restored)) {
		pr_perror("Can't create pipes");
		return 1;
	}

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		return 1;
	}

	snprintf(aux, sizeof(aux), "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto out_rd;
	}

	if (get_cgroup(orig, sizeof(orig)))
		goto out_um;

	snprintf(sub, sizeof(sub), "%s/%s", strcmp(orig, "/") ? orig : "", SUBNAME);
	snprintf(aux, sizeof(aux), "%s/%s", dirname, sub);
	if (mkdir(aux, 0700)) {
		pr_perror("Can't make %s", aux);
		goto out_um;
	}

	/* The task, and so its threads and children, are in a cgroup of their own. */
	if (cg_move(sub, "cgroup.procs"))
		goto out_rs;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out_mv;
	}
	if (pid == 0) {
		/* Back into the cgroup criu is in, away from the parent. */
		status = cg_move(orig, "cgroup.procs");
		write(child_pipe[1], &status, sizeof(status));
		if (status)
			exit(1);

		read(child_restored[0], &status, sizeof(status));
		status = cg_check(orig, "child");
		write(child_pipe[1], &status, sizeof(status));
		exit(0);
	}

	if (pthread_create(&thread, NULL, thread_fn, NULL)) {
		pr_perror("Can't create a thread");
		goto out_kill;
	}

	read(child_pipe[0], &status, sizeof(status));
	if (status)
		goto out_join;
	read(thread_pipe[0], &status, sizeof(status));
	if (status)
		goto out_join;

	test_daemon();
	test_waitsig();

	status = 0;
	write(child_restored[1], &status, sizeof(status));
	write(thread_restored[1], &status, sizeof(status));

	ret = cg_check(sub, "task") ? 1 : 0;

	read(child_pipe[0], &status, sizeof(status));
	if (status)
		ret = 1;
	read(thread_pipe[0], &status, sizeof(status));
	if (status)
		ret = 1;

	if (!ret)
		pass();

out_join:
	pthread_join(thread, NULL);
out_kill:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
out_mv:
	cg_move(orig, "cgroup.procs");
out_rs:
	snprintf(aux, sizeof(aux), "%s/%s", dirname, sub);
	rmdir(aux);
out_um:
	umount(dirname);
out_rd:
	rmdir(dirname);
	return ret;
}
