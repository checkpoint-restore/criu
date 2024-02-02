#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <pthread.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that cgroup layout of threads is preserved";
const char *test_author	= "Michał Cłapiński <mclapinski@google.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
#define SUBNAME	 "subcg_threads"
#define SUBNAME2 SUBNAME "/subsubcg"

static int cg_move(char *name)
{
	int cgfd, l;
	char paux[256];

	sprintf(paux, "%s/%s", dirname, name);
	mkdir(paux, 0600);

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

int p1[2], pr[2];

void *child(void *args)
{
	int status = cg_move(SUBNAME2);
	write(p1[1], &status, sizeof(status));

	if (status == 0) {
		read(pr[0], &status, sizeof(status));

		status = cg_check(SUBNAME2);
		write(p1[1], &status, sizeof(status));
	}

	pthread_exit(0);
}

int main(int argc, char **argv)
{
	char aux[64];
	int status;
	pthread_t thread;

	test_init(argc, argv);

	/*
	 * Pipe to talk to the kid.
	 * First, it reports that it's ready (int),
	 * then it reports the restore status (int).
	 */

	pipe(p1);

	/* "Restore happened" pipe */
	pipe(pr);

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

	pthread_create(&thread, NULL, child, NULL);

	status = -1;
	read(p1[0], &status, sizeof(status));
	if (status != 0) {
		pr_perror("Error moving into cgroups");
		close(pr[0]);
		goto out_rs;
	}

	test_daemon();
	test_waitsig();

	close(pr[1]);

	status = -1;
	read(p1[0], &status, sizeof(status));
	if (status != 0) {
		fail("child cg changed");
		goto out_rs;
	}

	pass();

out_rs:
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return 0;
}
