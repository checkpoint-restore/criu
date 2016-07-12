#include <sys/mman.h>
#include "zdtmtst.h"

#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP   16
#endif

const char *test_doc	= "Test shared memory with advises";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

struct mmap_data {
	void		*start;
	unsigned long	orig_flags;
	unsigned long	orig_madv;
	unsigned long	new_flags;
	unsigned long	new_madv;
};

#define MEM_SIZE (8192)

static int alloc_anon_mmap(struct mmap_data *m, int flags, int adv)
{
	m->start = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
			flags, -1, 0);
	if (m->start == MAP_FAILED) {
		pr_perror("mmap failed");
		return -1;
	}

	if (madvise(m->start, MEM_SIZE, adv)) {
		if (errno == EINVAL) {
			test_msg("madvise failed, no kernel support\n");
			munmap(m->start, MEM_SIZE);
			*m = (struct mmap_data){ };
		} else {
			pr_perror("madvise failed");
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct mmap_data m[5] = { };
	size_t i;

	test_init(argc, argv);

	test_msg("Alloc growsdown\n");
	if (alloc_anon_mmap(&m[0], MAP_PRIVATE | MAP_ANONYMOUS, MADV_DONTFORK))
		return -1;

	test_msg("Alloc locked/sequential\n");
	if (alloc_anon_mmap(&m[1], MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, MADV_SEQUENTIAL))
		return -1;

	test_msg("Alloc noreserve/dontdump\n");
	if (alloc_anon_mmap(&m[2], MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, MADV_DONTDUMP))
		return -1;

	test_msg("Alloc hugetlb/hugepage\n");
	if (alloc_anon_mmap(&m[3], MAP_PRIVATE | MAP_ANONYMOUS, MADV_HUGEPAGE))
		return -1;

	test_msg("Alloc dontfork/random|mergeable\n");
	if (alloc_anon_mmap(&m[4], MAP_PRIVATE | MAP_ANONYMOUS, MADV_MERGEABLE))
		return -1;

	test_msg("Fetch existing flags/adv\n");
	for (i = 0; i < sizeof(m)/sizeof(m[0]); i++) {
		if (get_smaps_bits((unsigned long)m[i].start,
				   &m[i].orig_flags,
				   &m[i].orig_madv))
			return -1;
	}

	test_daemon();
	test_waitsig();

	test_msg("Fetch restored flags/adv\n");
	for (i = 0; i < sizeof(m)/sizeof(m[0]); i++) {
		if (get_smaps_bits((unsigned long)m[i].start,
				   &m[i].new_flags,
				   &m[i].new_madv))
			return -1;

		if (m[i].orig_flags != m[i].new_flags) {
			pr_perror("Flags are changed %lx %lx -> %lx (%zu)",
			    (unsigned long)m[i].start,
			    m[i].orig_flags, m[i].new_flags, i);
			fail();
			return -1;
		}

		if (m[i].orig_madv != m[i].new_madv) {
			pr_perror("Madvs are changed %lx %lx -> %lx (%zu)",
			    (unsigned long)m[i].start,
			    m[i].orig_madv, m[i].new_madv, i);
			fail();
			return -1;
		}

	}

	pass();

	return 0;
}
