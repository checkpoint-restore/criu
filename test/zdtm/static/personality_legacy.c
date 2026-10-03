#include <errno.h>
#include <sys/personality.h>

#include "zdtmtst.h"

const char *test_doc = "Check that legacy core image (missing thread_core personality) skips restore";
const char *test_author = "srinivasr <sriniv4sreddy@gmail.com>";

#define PERSONA_QUERY 0xffffffffu

#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE 0x0040000
#endif

static int set_personality(unsigned int p)
{
	errno = 0;
	if (personality(p) == -1 && errno != 0)
		return -1;
	return 0;
}

static unsigned int get_personality(void)
{
	int p;

	errno = 0;
	p = personality(PERSONA_QUERY);
	if (p == -1 && errno != 0) {
		fail("can't query personality");
		return ~0u;
	}
	return (unsigned int)p;
}

int main(int argc, char **argv)
{
	unsigned int persona, after;

	test_init(argc, argv);

	persona = get_personality();
	if (persona == ~0u)
		return 1;

	/* Set ADDR_NO_RANDOMIZE before dump */
	if (set_personality(persona | ADDR_NO_RANDOMIZE)) {
		fail("can't set ADDR_NO_RANDOMIZE");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * During C/R, the pre-restore hook stripped field 18 from thread_core
	 * and injected the legacy mangled decimal value 400000 into tc->personality.
	 * CRIU must detect the missing field 18, skip personality restore,
	 * and NOT apply the mangled value.
	 * Restored task must retain default personality (0).
	 */
	after = get_personality();
	if (after == ~0u)
		return 1;

	if (after != 0) {
		fail("legacy personality was erroneously applied: 0x%08x (expected default 0)", after);
		return 1;
	}

	pass();
	return 0;
}
