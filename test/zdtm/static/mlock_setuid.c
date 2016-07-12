#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include "zdtmtst.h"

#define MEM_SIZE (69632)

int main(int argc, char **argv)
{
	int ret;
	void *start;
	unsigned long new_flags = 0;
	unsigned long new_madv = 0;
	test_init(argc, argv);

	test_msg("Alloc vma of size %d\n", MEM_SIZE);
	start = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
	             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (start == MAP_FAILED) {
		pr_perror("mmap failed");
		return -1;
	}

	test_msg("Lock vma from %p to %lx\n",
			start, (unsigned long)start + MEM_SIZE);
	ret = mlock(start, MEM_SIZE);
	if (ret < 0) {
		pr_perror("mlock");
		return -1;
	}

	test_daemon();

	test_msg("Setuid to 18943\n");
	ret = setuid(18943);
	if (ret < 0) {
		pr_perror("setuid");
		return -1;
	}

	test_waitsig();

	ret = get_smaps_bits((unsigned long)start, &new_flags, &new_madv);
	if (ret < 0)
		return -1;

	test_msg("Check smaps flags for MAP_LOCKED\n");
	if (new_flags & MAP_LOCKED) {
		pass();
	} else {
		fail("Vma is not locked after c/r\n");
		return -1;
	}

	return 0;
}
