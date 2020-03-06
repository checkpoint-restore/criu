#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <linux/limits.h>
#include <signal.h>
#include "zdtmtst.h"

/* Enabling the right policy happens in selinux00.hook and selinx00.checkskip */

const char *test_doc	= "Check that a SELinux socket context is restored";
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

int set_sockcreate(void)
{
	int fd, len;

	fd = open("/proc/self/attr/sockcreate", O_WRONLY);
	if (fd < 0) {
		fail("Could not open /proc/self/attr/sockcreate\n");
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

int check_sockcreate(void)
{
	int fd;
	char context[1024];
	int len;


	fd = open("/proc/self/attr/sockcreate", O_RDONLY);
	if (fd < 0) {
		fail("Could not open /proc/self/attr/sockcreate\n");
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

int check_sockcreate_empty(void)
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
	int sk;
	char ctx[1024];
	test_init(argc, argv);

	if (check_for_selinux()) {
		skip("SELinux not found on this system.");
		test_daemon();
		test_waitsig();
		pass();
		return 0;
	}

#ifdef USING_SOCKCREATE
	if (set_sockcreate())
		return -1;
#else
	if (check_sockcreate_empty())
		return -1;

	if (setprofile())
		return -1;

	if (check_sockcreate_empty())
		return -1;
#endif

	/* Open our test socket */
	sk = socket(AF_INET, SOCK_STREAM, 0);
	memset(ctx, 0, 1024);
	/* Read out the socket label */
	if (fgetxattr(sk, "security.selinux", ctx, 1024) == -1) {
		fail("Reading xattr 'security.selinux' failed.\n");
		return -1;
	}
	if (strncmp(ctx, CONTEXT, strlen(CONTEXT)) != 0) {
		fail("Wrong SELinux context %s expected %s\n", ctx, CONTEXT);
		return -1;
	}
	memset(ctx, 0, 1024);

	test_daemon();
	test_waitsig();

	/* Read out the socket label again */

	if (fgetxattr(sk, "security.selinux", ctx, 1024) == -1) {
		fail("Reading xattr 'security.selinux' failed.\n");
		return -1;
	}
	if (strncmp(ctx, CONTEXT, strlen(CONTEXT)) != 0) {
		fail("Wrong SELinux context %s expected %s\n", ctx, CONTEXT);
		return -1;
	}

#ifdef USING_SOCKCREATE
	if (check_sockcreate())
		return -1;
#else
	if (check_sockcreate_empty())
		return -1;
#endif

	pass();

	return 0;
}
