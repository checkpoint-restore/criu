#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that cgroups layout is preserved";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
#define SUBNAME	"subcg00"
#define SUBNAME2 SUBNAME"/subsubcg"

static int cg_move(char *name)
{
	int cgfd, l;
	char paux[256];

	sprintf(paux, "%s/%s", dirname, name);
	mkdir(paux, 0600);

	sprintf(paux, "%s/%s/tasks", dirname, name);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		err("Can't open tasks");
		return -1;
	}

	l = write(cgfd, "0", 2);
	close(cgfd);

	if (l < 0) {
		err("Can't move self to subcg");
		return -1;
	}

	return 0;
}

static int cg_check(char *name)
{
	int found = 0;
	FILE *cgf;
	char paux[256], aux[128];

	cgf = fopen("/proc/self/cgroup", "r");
	if (cgf == NULL)
		return -1;

	sprintf(aux, "name=%s:/%s\n", cgname, name);
	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strchr(paux, ':') + 1;
		test_msg("CMP [%s] vs [%s]\n", s, aux);
		if (!strcmp(s, aux)) {
			found = 1;
			break;
		}
	}

	fclose(cgf);

	return found ? 0 : -1;
}

int main(int argc, char **argv)
{
	char aux[64];
	int p1[2], p2[2], pr[2], status;

	test_init(argc, argv);

	/*
	 * Pipes to talk to two kids.
	 * First, they report that they are ready (int),
	 * then they report the restore status (int).
	 */

	pipe(p1);
	pipe(p2);

	/* "Restore happened" pipe */
	pipe(pr);

	if (mkdir(dirname, 0700) < 0) {
		err("Can't make dir");
		goto out;
	}

	sprintf(aux, "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		err("Can't mount cgroups");
		goto out_rd;
	}

	if (cg_move(SUBNAME))
		goto out_rs;

	if (fork() == 0) {
		if (fork() == 0) {
			/*
			 * 2nd level kid -- moves into its own
			 * cgroup and triggers slow-path cg_set
			 * restore in criu
			 */

			close(p1[0]);
			close(p1[1]);
			close(p2[0]);
			close(pr[1]);

			status = cg_move(SUBNAME2);
			write(p2[1], &status, sizeof(status));

			if (status == 0) {
				read(pr[0], &status, sizeof(status));

				status = cg_check(SUBNAME2);
				write(p2[1], &status, sizeof(status));
			}

			exit(0);
		}

		/*
		 * 1st level kid -- inherits cgroup from
		 * parent and triggers fast-path cg_set
		 * restore in criu
		 */

		close(p1[0]);
		close(p2[0]);
		close(p2[1]);
		close(pr[1]);

		status = 0;
		write(p1[1], &status, sizeof(status));

		read(pr[0], &status, sizeof(status));

		status = cg_check(SUBNAME);
		write(p1[1], &status, sizeof(status));

		exit(0);
	}

	close(p1[1]);
	close(p2[1]);
	close(pr[0]);

	status = -1;
	read(p1[0], &status, sizeof(status));
	if (status != 0)
		goto out_ks;

	status = -1;
	read(p2[0], &status, sizeof(status));
	if (status != 0)
		goto out_ks;

	test_daemon();
	test_waitsig();

	close(pr[1]);

	if (cg_check(SUBNAME)) {
		fail("Top level task cg changed");
		goto out_rs;
	}

	status = -1;
	read(p1[0], &status, sizeof(status));
	if (status != 0) {
		fail("1st level task cg changed");
		goto out_rs;
	}

	status = -1;
	read(p2[0], &status, sizeof(status));
	if (status != 0) {
		fail("2nd level task cg changed");
		goto out_rs;
	}

	pass();

out_rs:
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return 0;

out_ks:
	err("Error moving into cgroups");
	close(pr[0]);
	goto out_rs;
}
