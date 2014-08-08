#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that cgroups layout is preserved";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
#define SUBNAME	"subcg"

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

static void cg_cleanup(void)
{
	char paux[256];

	sprintf(paux, "%s/%s", dirname, SUBNAME);
	rmdir(paux);
}

int main(int argc, char **argv)
{
	char aux[64];

	test_init(argc, argv);

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

	test_daemon();
	test_waitsig();

	if (cg_check(SUBNAME)) {
		fail("Top level task cg changed");
		goto out_rs;
	}

	pass();

out_rs:
	cg_cleanup();
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return 0;
}
