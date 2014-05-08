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
static const char *subname = "subcg";

int main(int argc, char **argv)
{
	int cgfd, l, ret = 1;
	char aux[32], paux[1024];
	FILE *cgf;

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

	sprintf(paux, "%s/%s", dirname, subname);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	sprintf(paux, "%s/%s/tasks", dirname, subname);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		err("Can't open tasks");
		goto out_rs;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		err("Can't move self to subcg");
		goto out_rs;
	}

	close(cgfd);

	test_daemon();
	test_waitsig();

	cgf = fopen("/proc/self/cgroup", "r");
	if (cgf == NULL) {
		fail("No cgroups file");
		goto out_rs;
	}

	sprintf(aux, "name=%s:/%s\n", cgname, subname);
	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strchr(paux, ':') + 1;
		test_msg("CMP [%s] vs [%s]\n", s, aux);
		if (!strcmp(s, aux)) {
			ret = 0;
			break;
		}
	}

	fclose(cgf);

	if (!ret)
		pass();
	else
		fail("Task is not in subgroups");

out_rs:
	sprintf(paux, "%s/%s", dirname, subname);
	rmdir(paux);
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return ret;
}
