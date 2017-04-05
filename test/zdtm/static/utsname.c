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

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (sethostname(ZDTM_NODE, sizeof(ZDTM_NODE))) {
		pr_perror("Unable to set hostname");
		return 1;
	}

	if (setdomainname(ZDTM_DOMAIN, sizeof(ZDTM_DOMAIN))) {
		pr_perror("Unable to set domainname");
		return 1;
	}

	test_daemon();
	test_waitsig();

	uname(&after);

	if (strcmp(ZDTM_NODE, after.nodename)) {
		fail("Nodename doesn't match");
		return 1;
	}
	if (strcmp(ZDTM_DOMAIN, after.domainname)) {
		fail("Domainname doesn't match");
		return 1;
	}

	pass();
	return 0;
}
