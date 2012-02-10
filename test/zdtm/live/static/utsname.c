#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that utsname hasn't changed";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

static struct utsname after;

#define ZDTM_NODE "zdtm.nodename.ru"
#define ZDTM_DOMAIN "zdtm.nodename.ru"

static int test_fn(int argc, char **argv)
{
	int ret;
	int fd;

	fd = open("/proc/sys/kernel/hostname", O_WRONLY);
	if (fd < 0) {
		err("Can't open hostname\n");
		return 1;
	}

	ret = write(fd, ZDTM_NODE, sizeof(ZDTM_NODE));
	if (ret != sizeof(ZDTM_NODE)) {
		err("Can't write nodename\n");
		return 1;
	}

	close(fd);

	fd = open("/proc/sys/kernel/domainname", O_WRONLY);
	if (fd < 0) {
		err("Can't open domainname\n");
		return -errno;
	}

	ret = write(fd, ZDTM_DOMAIN, sizeof(ZDTM_DOMAIN));
	if (ret != sizeof(ZDTM_DOMAIN)) {
		err("Can't write domainname\n");
		return 1;
	}

	close(fd);

	test_daemon();
	test_waitsig();

	uname(&after);

	if (strcmp(ZDTM_NODE, after.nodename)) {
		fail("Nodename doesn't match");
		return 1;
	}
	if (strcmp(ZDTM_DOMAIN, after.__domainname)) {
		fail("Domainname doesn't match");
		return 1;
	}

	pass();
	return 0;
}

int main(int argc, char **argv)
{
	test_init_ns(argc, argv, CLONE_NEWUTS, test_fn);
	return 0;
}
