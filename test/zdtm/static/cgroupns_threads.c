#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include "zdtmtst.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

const char *test_doc = "Check that threads of a non-root task in a cgroup NS "
		       "are restored in their cgroup and share one cgroup set";
const char *test_author = "Joseph Crivello <joe@jetout.com>";

/* we need dirname before test_init() here */
char *dirname = "cgroupns_threads.test";
static const char *cgname = "zdtmtst";
#define SUBNAME	   "subcg_ns_threads"
#define NR_THREADS 16

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

/* Check that the calling thread is in the root of its cgroup namespace. */
static int cg_check(const char *who)
{
	char line[512], name[64], *path = NULL;
	FILE *f;

	f = fopen("/proc/thread-self/cgroup", "r");
	if (!f) {
		pr_perror("Can't open /proc/thread-self/cgroup");
		return -1;
	}

	ssprintf(name, ":name=%s:", cgname);
	while (fgets(line, sizeof(line), f)) {
		path = strstr(line, name);
		if (path)
			break;
	}
	fclose(f);

	if (!path) {
		pr_err("No %s cgroup found\n", cgname);
		return -1;
	}

	path += strlen(name);
	path[strcspn(path, "\n")] = '\0';
	if (strcmp(path, "/")) {
		fail("The %s is in %s, expected /", who, path);
		return -1;
	}

	return 0;
}

/* The main task closes the write end once it is restored. */
static int rst_sync[2];

static void *thread_fn(void *arg)
{
	char c;

	if (read(rst_sync[0], &c, sizeof(c)) < 0) {
		pr_perror("Can't wait for the restore");
		return (void *)1;
	}

	return cg_check("thread") ? (void *)1 : NULL;
}

static int child_fn(int ready_fd)
{
	pthread_t threads[NR_THREADS];
	int i, err, ret = 0;
	void *res;
	char c = 0;

	for (i = 0; i < NR_THREADS; i++) {
		err = pthread_create(&threads[i], NULL, thread_fn, NULL);
		if (err) {
			pr_err("Can't create a thread: %s\n", strerror(err));
			return 1;
		}
	}

	if (write(ready_fd, &c, sizeof(c)) != sizeof(c)) {
		pr_perror("Can't report to the parent");
		return 1;
	}

	for (i = 0; i < NR_THREADS; i++) {
		if (pthread_join(threads[i], &res) || res)
			ret = 1;
	}

	if (cg_check("child"))
		ret = 1;

	return ret;
}

int main(int argc, char **argv)
{
	int exit_code = -1, ready[2], status;
	char path[PATH_MAX], c;
	pid_t pid;

	/*
	 * The cgroup namespace has to be unshared while being in a
	 * non-root cgroup, otherwise there is no cgns prefix to dump.
	 */
	if (mount_and_add(cgname, SUBNAME) < 0)
		return -1;

	if (unshare(CLONE_NEWCGROUP) < 0) {
		pr_perror("Can't unshare cgns");
		goto out;
	}

	test_init(argc, argv);

	if (pipe(ready) || pipe(rst_sync)) {
		pr_perror("Can't create pipes");
		goto out;
	}

	/*
	 * Only the root task is looked at from inside of its cgroup
	 * namespace on dump, so the threads have to be in another task.
	 */
	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		close(ready[0]);
		close(rst_sync[1]);
		exit(child_fn(ready[1]));
	}
	close(ready[1]);

	if (read(ready[0], &c, sizeof(c)) != sizeof(c)) {
		pr_err("The child is not ready\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}

	test_daemon();
	test_waitsig();

	/* Let the child and its threads check where they are. */
	close(rst_sync[1]);

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Can't wait for the child");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("The child exited with status %d", status);
		goto out;
	}

	if (cg_check("task"))
		goto out;

	exit_code = 0;
	pass();

out:
	ssprintf(path, "%s/%s/%s", dirname, cgname, SUBNAME);
	rmdir(path);
	ssprintf(path, "%s/%s", dirname, cgname);
	umount(path);
	rmdir(path);
	rmdir(dirname);
	return exit_code;
}
