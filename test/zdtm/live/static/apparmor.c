#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <signal.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that an apparmor profile is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#define PROFILE "criu_test"

int setprofile()
{
	char profile[1024];
	int fd, len;

	len = snprintf(profile, sizeof(profile), "changeprofile " PROFILE);
	if (len < 0 || len >= sizeof(profile)) {
		fail("bad sprintf\n");
		return -1;
	}

	fd = open("/proc/self/attr/current", O_WRONLY);
	if (fd < 0) {
		fail("couldn't open fd\n");
		return -1;
	}

	/* apparmor wants this in exactly one write, so we use write() here
	 * vs. fprintf Just To Be Sure */
	len = write(fd, profile, len);
	close(fd);

	if (len < 0) {
		fail("couldn't write profile\n");
		return -1;
	}

	return 0;
}

int checkprofile()
{
	FILE *f;
	char path[PATH_MAX], profile[1024];
	int len;

	sprintf(path, "/proc/self/attr/current");

	f = fopen(path, "r");
	if (!f) {
		fail("couldn't open lsm current\n");
		return -1;
	}

	len = fscanf(f, "%[^ \n]s", profile);
	fclose(f);
	if (len != 1) {
		fail("wrong number of items scanned %d\n", len);
		return -1;
	}

	if (strcmp(profile, PROFILE) != 0) {
		fail("bad profile .%s. expected .%s.\n", profile, PROFILE);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	setprofile();

	test_daemon();
	test_waitsig();

	if (checkprofile(0) == 0)
		pass();

	return 0;
}
