#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#include "zdtmtst.h"

const char *test_doc	= "Check dump and restore a net.unix.max_dgram_qlen sysctl parameter in subns";

#define CONF_UNIX_PARAM "/proc/sys/net/unix/max_dgram_qlen"

int main(int argc, char **argv)
{
	char cmd[128];
	FILE *fp;
	int ret, test_max_dgram_qlen = 321, max_dgram_qlen = 0;
	test_init(argc, argv);

	if (unshare(CLONE_NEWNET)) {
		perror("unshare");
		return 1;
	}

	sprintf(cmd, "echo %d > %s", test_max_dgram_qlen, CONF_UNIX_PARAM);
	if (system(cmd)) {
		pr_perror("Can't change %s", CONF_UNIX_PARAM);
		return -1;
	}

	fp = fopen(CONF_UNIX_PARAM, "r+");
	if (fp == NULL) {
		pr_perror("fopen");
		return -1;
	}

	ret = fscanf(fp, "%d", &max_dgram_qlen);
	if (ret != 1) {
		pr_perror("fscanf");
		fclose(fp);
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (test_max_dgram_qlen != max_dgram_qlen) {
		fail();
		return 1;
	}

	pass();
	return 0;
}
