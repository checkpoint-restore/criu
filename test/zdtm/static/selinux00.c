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

/* Enabling the right policy happens in selinux00.hook and selinx00.checkskip */

const char *test_doc	= "Check that a SELinux profile is restored";
const char *test_author	= "Adrian Reber <areber@redhat.com>";

/* This is all based on Tycho's apparmor code */

#define CONTEXT "unconfined_u:unconfined_r:unconfined_dbusd_t:s0"

/*
 * This is used to store the state of SELinux. For this test
 * SELinux is switched to permissive mode and later the previous
 * SELinux state is restored.
 */
char state;

int check_for_selinux(void)
{
	if (access("/sys/fs/selinux", F_OK) == 0)
		return 0;
	return 1;
}

int setprofile(void)
{
	int fd, len;

	fd = open("/proc/self/attr/current", O_WRONLY);
	if (fd < 0) {
		fail("Could not open /proc/self/attr/current\n");
		return -1;
	}

	len = write(fd, CONTEXT, strlen(CONTEXT));
	close(fd);

	if (len < 0) {
		fail("Could not write context\n");
		return -1;
	}

	return 0;
}

int checkprofile(void)
{
	int fd;
	char context[1024];
	int len;


	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd < 0) {
		fail("Could not open /proc/self/attr/current\n");
		return -1;
	}

	len = read(fd, context, strlen(CONTEXT));
	close(fd);
	if (len != strlen(CONTEXT)) {
		fail("SELinux context has unexpected length %d, expected %zd\n",
			len, strlen(CONTEXT));
		return -1;
	}

	if (strncmp(context, CONTEXT, strlen(CONTEXT)) != 0) {
		fail("Wrong SELinux context %s expected %s\n", context, CONTEXT);
		return -1;
	}

	return 0;
}

int check_sockcreate(void)
{
	char *output = NULL;
	FILE *f = fopen("/proc/self/attr/sockcreate", "r");
	int ret = fscanf(f, "%ms", &output);
	fclose(f);

	if (ret >= 1) {
		free(output);
		/* sockcreate should be empty, if fscanf found something
		 * it is wrong.*/
		fail("sockcreate should be empty\n");
		return -1;
	}

	if (output) {
		free(output);
		/* Same here, output should still be NULL. */
		fail("sockcreate should be empty\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (check_for_selinux()) {
		skip("SELinux not found on this system.");
		test_daemon();
		test_waitsig();
		pass();
		return 0;
	}

	if (check_sockcreate())
		return -1;

	if (setprofile())
		return -1;

	if (check_sockcreate())
		return -1;

	test_daemon();
	test_waitsig();

	if (check_sockcreate())
		return -1;

	if (checkprofile() == 0)
		pass();

	return 0;
}
