#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include "zdtmtst.h"

const char *test_doc = "Check if we can use vDSO after restore\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org";

int main(int argc, char *argv[])
{
	struct timeval tv;
	struct timezone tz;

	test_init(argc, argv);
	test_msg("%s pid %d\n", argv[0], getpid());

	gettimeofday(&tv, &tz);
	test_msg("%d time: %10li\n", getpid(), tv.tv_sec);

	test_daemon();
	test_waitsig();

	/* this call will fail if vDSO is corrupted */
	gettimeofday(&tv, &tz);
	test_msg("%d time: %10li\n", getpid(), tv.tv_sec);

	pass();

	return 0;
}
