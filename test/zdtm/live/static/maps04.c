#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include "zdtmtst.h"

#define MEM_SIZE (1L << 29)

const char *test_doc	= "Test big mappings";
const char *test_author	= "Andrew Vagin <avagin@openvz.org";

int main(int argc, char ** argv)
{
	void *m;
	uint32_t crc;
	int i;

	test_init(argc, argv);

	m = mmap(NULL, MEM_SIZE, PROT_WRITE | PROT_READ,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (m == MAP_FAILED) {
		fail();
		return 1;
	}

	crc = ~0;
	datagen(m, MEM_SIZE, &crc);

	for (i = 0; i < MEM_SIZE / (1<<20); i++)
		if (mprotect(m + (lrand48() * PAGE_SIZE % MEM_SIZE), PAGE_SIZE, PROT_NONE)) {
			err("mprotect");
			return 1;
		}

	test_daemon();
	test_waitsig();

	if (mprotect(m, MEM_SIZE, PROT_READ))
		err("mprotect");

	crc = ~0;
	if (datachk(m, MEM_SIZE, &crc))
		fail("Mem corrupted");
	else
		pass();

	return 0;
}
