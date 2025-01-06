#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <pthread.h>
#include "zdtmtst.h"

const char *test_doc = "Check that cgroup layout of threads is preserved";
const char *test_author = "Michał Cłapiński <mclapinski@google.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
#define SUBNAME	 "subcg_threads"
#define SUBNAME2 SUBNAME "/subsubcg"

#define exit_group(code) syscall(__NR_exit_group, code)

static int cg_move(char *name)
{
	int cgfd, l;
	char paux[256];

	sprintf(paux, "%s/%s", dirname, name);
	if (mkdir(paux, 0600)) {
		pr_perror("Can't create %s", paux);
		return -1;
	}

	sprintf(paux, "%s/%s/tasks", dirname, name);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks");
		return -1;
	}

	l = write(cgfd, "0", 2);
	close(cgfd);

	if (l < 0) {
		pr_perror("Can't move self to subcg");
		return -1;
	}

	return 0;
}

static int cg_check(char *name)
{
	int found = 0;
	FILE *cgf;
	char paux[256], aux[128];

	cgf = fopen("/proc/thread-self/cgroup", "r");
	if (cgf == NULL)
		return -1;

	sprintf(aux, "name=%s:/%s", cgname, name);
	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strchr(paux, ':') + 1;
		s[strlen(s) - 1] = '\0';
		test_msg("CMP [%s] vs [%s]\n", s, aux);
		if (!strcmp(s, aux)) {
			found = 1;
			break;
		}
	}

	fclose(cgf);

	return found ? 0 : -1;
}

int th_sync[2], rst_sync[2];

void *thread_fn(void *args)
{
	int status = cg_move(SUBNAME2);

	if (write(th_sync[1], &status, sizeof(status)) != sizeof(status)) {
		pr_perror("write");
		exit_group(1);
	}

	if (status == 0) {
		if (read(rst_sync[0], &status, sizeof(status)) < 0) {
			pr_perror("read");
			exit_group(1);
		}

		status = cg_check(SUBNAME2);
		if (write(th_sync[1], &status, sizeof(status)) != sizeof(status)) {
			pr_perror("write");
			exit_group(1);
		}
	}

	pthread_exit(0);
}

int main(int argc, char **argv)
{
	int status, exit_code = 1;
	pthread_t thread;
	char aux[64];

	test_init(argc, argv);

	/*
	 * Pipe to talk to the kid.
	 * First, it reports that it's ready (int),
	 * then it reports the restore status (int).
	 */

	if (pipe(th_sync)) {
		pr_perror("pipe");
		return 1;
	}

	/* "Restore happened" pipe */
	if (pipe(rst_sync)) {
		pr_perror("pipe");
		return 1;
	}

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		goto out;
	}

	sprintf(aux, "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto out_rd;
	}

	if (cg_move(SUBNAME))
		goto out_rs;

	if (pthread_create(&thread, NULL, thread_fn, NULL)) {
		pr_perror("Can't create a new thread");
		goto out_rs;
	}

	status = -1;
	read(th_sync[0], &status, sizeof(status));
	if (status != 0) {
		pr_perror("Error moving into cgroups");
		close(rst_sync[0]);
		goto out_rs;
	}

	test_daemon();
	test_waitsig();

	close(rst_sync[1]);

	status = -1;
	if (read(th_sync[0], &status, sizeof(status)) < 0) {
		pr_perror("read");
		goto out_rs;
	}
	if (status != 0) {
		fail("child cg changed");
		goto out_rs;
	}

	pass();
	exit_code = 0;

out_rs:
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return exit_code;
}
