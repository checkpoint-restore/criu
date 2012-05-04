#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "zdtmtst.h"

#ifndef F_SETSIG
#define F_SETSIG	10	/* for sockets. */
#define F_GETSIG	11	/* for sockets. */
#endif

const char *test_doc	= "Check for eventfs";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#define EVENTFD_INITIAL	30
#define EVENTFD_FINAL	90

int main(int argc, char *argv[])
{
	int efd, ret;
	uint64_t v = EVENTFD_INITIAL;

	test_init(argc, argv);

	efd = eventfd((unsigned int)v, EFD_NONBLOCK);
	if (efd < 0) {
		fail("eventfd");
		exit(1);
	}

	test_msg("created eventfd with %lx\n", v);

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		fail("write");
		exit(1);
	}

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		fail("write");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	ret = read(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		fail("write");
		exit(1);
	}

	if (v != EVENTFD_FINAL) {
		fail("EVENTFD_FINAL mismatch\n");
		exit(1);
	}

	pass();
	return 0;
}
