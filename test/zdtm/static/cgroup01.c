#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"

const char *test_doc = "Check that empty cgroups are preserved";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
static const char *subname = "subcg01";
static const char *empty = "empty";

int main(int argc, char **argv)
{
	int cgfd, l, ret = 1, i;
	char aux[1024], paux[1024];
	FILE *cgf;
	struct stat st;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		goto out;
	}

	sprintf(aux, "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto out_rd;
	}

	sprintf(paux, "%s/%s", dirname, subname);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	sprintf(paux, "%s/%s/tasks", dirname, subname);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks");
		goto out_rs;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		pr_perror("Can't move self to subcg");
		goto out_rs;
	}

	for (i = 0; i < 2; i++) {
		sprintf(paux, "%s/%s/%s.%d", dirname, subname, empty, i);
		if (mkdir(paux, 0600)) {
			pr_perror("mkdir %s", paux);
			goto out_rs;
		}
	}

	test_daemon();
	test_waitsig();

	cgf = fopen("/proc/self/mountinfo", "r");
	if (cgf == NULL) {
		fail("No mountinfo file");
		goto out_rs;
	}

	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strstr(paux, cgname);
		if (!s)
			continue;

		sscanf(paux, "%*d %*d %*d:%*d %*s %s", aux);
		test_msg("found cgroup at %s\n", aux);

		for (i = 0; i < 2; i++) {
			ssprintf(paux, "%s/%s/%s.%d", aux, subname, empty, i);

			if (stat(paux, &st)) {
				fail("couldn't stat %s", paux);
				ret = -1;
				goto out_close;
			}

			if (!S_ISDIR(st.st_mode)) {
				fail("%s is not a directory", paux);
				ret = -1;
				goto out_close;
			}
		}

		pass();
		ret = 0;
		goto out_close;
	}

	fail("empty cgroup not found!");

out_close:
	fclose(cgf);
out_rs:
	umount(dirname);
out_rd:
	rmdir(dirname);
out:
	return ret;
}
