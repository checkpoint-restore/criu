#include <string.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check UTS state and RLIMIT_NOFILE survive userns restore";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

#define ZDTM_NODE   "rootless-uts-rlimit"
#define ZDTM_DOMAIN "rootless-uts-domain"
#define NOFILE_CUR  64
#define NOFILE_MAX  512

static int check_state(void)
{
	struct rlimit rlim;
	struct utsname uts;

	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		pr_perror("getrlimit");
		return -1;
	}

	if (rlim.rlim_cur != NOFILE_CUR || rlim.rlim_max != NOFILE_MAX) {
		fail("RLIMIT_NOFILE is %lu:%lu, expected %u:%u",
		     (unsigned long)rlim.rlim_cur, (unsigned long)rlim.rlim_max,
		     NOFILE_CUR, NOFILE_MAX);
		return -1;
	}

	if (uname(&uts)) {
		pr_perror("uname");
		return -1;
	}

	if (strcmp(uts.nodename, ZDTM_NODE)) {
		fail("nodename is %s, expected %s", uts.nodename, ZDTM_NODE);
		return -1;
	}

	if (strcmp(uts.domainname, ZDTM_DOMAIN)) {
		fail("domainname is %s, expected %s", uts.domainname, ZDTM_DOMAIN);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit rlim = {
		.rlim_cur = NOFILE_CUR,
		.rlim_max = NOFILE_MAX,
	};

	test_init(argc, argv);

	if (sethostname(ZDTM_NODE, strlen(ZDTM_NODE))) {
		pr_perror("sethostname");
		return 1;
	}

	if (setdomainname(ZDTM_DOMAIN, strlen(ZDTM_DOMAIN))) {
		pr_perror("setdomainname");
		return 1;
	}

	if (setrlimit(RLIMIT_NOFILE, &rlim)) {
		pr_perror("setrlimit");
		return 1;
	}

	if (check_state())
		return 1;

	test_daemon();
	test_waitsig();

	if (check_state())
		return 1;

	pass();
	return 0;
}
