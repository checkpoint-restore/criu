#include <libaio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check that plain io_setup works";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	int ret;
	io_context_t ctx = 0;

	test_init(argc, argv);

	if (io_setup(1, &ctx) < 0) {
		pr_perror("Can't setup io ctx");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = io_getevents(ctx, 0, 1, NULL, NULL);
	if (ret != 0) {
		if (ret < 0)
			fail("IO ctx lost (%d)", ret);
		else
			fail("IO ctx screwed up (%d)", ret);
	} else
		pass();

	return 0;
}
