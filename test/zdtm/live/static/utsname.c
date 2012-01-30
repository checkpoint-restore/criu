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

static void test_fn(void)
{
	int ret;
	int fd;

	fd = open("/proc/sys/kernel/hostname", O_WRONLY);
	if (fd < 0) {
		err("Can't open hostname\n");
		return;
	}

	ret = write(fd, ZDTM_NODE, sizeof(ZDTM_NODE));
	if (ret != sizeof(ZDTM_NODE)) {
		err("Can't write nodename\n");
		return;
	}

	close(fd);

	fd = open("/proc/sys/kernel/domainname", O_WRONLY);
	if (fd < 0) {
		err("Can't open domainname\n");
		return;
	}

	ret = write(fd, ZDTM_DOMAIN, sizeof(ZDTM_DOMAIN));
	if (ret != sizeof(ZDTM_DOMAIN)) {
		err("Can't write domainname\n");
		return;
	}

	close(fd);

	test_daemon();
	test_waitsig();

	uname(&after);

	ret = 1;

	if (strcmp(ZDTM_NODE, after.nodename)) {
		ret = 0;
		fail("Nodename doesn't match");
	}
	if (strcmp(ZDTM_DOMAIN, after.__domainname)) {
		ret = 0;
		fail("Domainname doesn't match");
	}

	if (ret)
		pass();
}

int main(int argc, char **argv)
{
	test_init_ns(argc, argv, CLONE_NEWUTS, test_fn);
	return -1;
}
