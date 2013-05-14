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

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0x40000
#endif

#ifndef MADV_HUGEPAGE
# define MADV_HUGEPAGE 14
#endif

#ifndef MADV_NOHUGEPAGE
# define MADV_NOHUGEPAGE 15
#endif

#ifndef MADV_DONTDUMP
# define MADV_DONTDUMP 16
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

static void parse_vmflags(char *buf, unsigned long *flags, unsigned long *madv)
{
	char *tok;

	if (!buf[0])
		return;

	tok = strtok(buf, " \n");
	if (!tok)
		return;

#define _vmflag_match(_t, _s) (_t[0] == _s[0] && _t[1] == _s[1])

	do {
		/* mmap() block */
		if (_vmflag_match(tok, "gd"))
			*flags |= MAP_GROWSDOWN;
		else if (_vmflag_match(tok, "lo"))
			*flags |= MAP_LOCKED;
		else if (_vmflag_match(tok, "nr"))
			*flags |= MAP_NORESERVE;
		else if (_vmflag_match(tok, "ht"))
			*flags |= MAP_HUGETLB;

		/* madvise() block */
		if (_vmflag_match(tok, "sr"))
			*madv |= (1ul << MADV_SEQUENTIAL);
		else if (_vmflag_match(tok, "rr"))
			*madv |= (1ul << MADV_RANDOM);
		else if (_vmflag_match(tok, "dc"))
			*madv |= (1ul << MADV_DONTFORK);
		else if (_vmflag_match(tok, "dd"))
			*madv |= (1ul << MADV_DONTDUMP);
		else if (_vmflag_match(tok, "mg"))
			*madv |= (1ul << MADV_MERGEABLE);
		else if (_vmflag_match(tok, "hg"))
			*madv |= (1ul << MADV_HUGEPAGE);
		else if (_vmflag_match(tok, "nh"))
			*madv |= (1ul << MADV_NOHUGEPAGE);

		/*
		 * Anything else is just ignored.
		 */
	} while ((tok = strtok(NULL, " \n")));

#undef _vmflag_match
}

#define is_hex_digit(c)				\
	(((c) >= '0' && (c) <= '9')	||	\
	 ((c) >= 'a' && (c) <= 'f')	||	\
	 ((c) >= 'A' && (c) <= 'F'))

static int is_vma_range_fmt(char *line, unsigned long *start, unsigned long *end)
{
	char *p = line;
	while (*line && is_hex_digit(*line))
		line++;

	if (*line++ != '-')
		return 0;

	while (*line && is_hex_digit(*line))
		line++;

	if (*line++ != ' ')
		return 0;

	sscanf(p, "%lx-%lx", start, end);
	return 1;
}

static int get_smaps_bits(unsigned long where, unsigned long *flags, unsigned long *madv)
{
	unsigned long start = 0, end = 0;
	FILE *smaps = NULL;
	char buf[1024];
	int found = 0;

	if (!where)
		return 0;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps) {
		err("Can't open smaps: %m");
		return -1;
	}

	while (fgets(buf, sizeof(buf), smaps)) {
		is_vma_range_fmt(buf, &start, &end);

		if (!strncmp(buf, "VmFlags: ", 9) && start == where) {
			found = 1;
			parse_vmflags(buf, flags, madv);
			break;
		}
	}

	fclose(smaps);

	if (!found) {
		err("VmFlags not found for %lx\n", where);
		return -1;
	}

	return 0;
}

#define MEM_SIZE (8192)

static int alloc_anon_mmap(struct mmap_data *m, int flags, int adv)
{
	m->start = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
			flags, -1, 0);
	if (m->start == MAP_FAILED) {
		err("mmap failed: %m");
		return -1;
	}

	if (madvise(m->start, MEM_SIZE, adv)) {
		if (errno == EINVAL) {
			test_msg("madvise failed, no kernel support\n");
			munmap(m->start, MEM_SIZE);
			*m = (struct mmap_data){ };
		} else {
			err("madvise failed: %m");
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
			err("Flags are changed %lx %lx -> %lx (%d)\n",
			    (unsigned long)m[i].start,
			    m[i].orig_flags, m[i].new_flags, i);
			fail();
			return -1;
		}

		if (m[i].orig_madv != m[i].new_madv) {
			err("Madvs are changed %lx %lx -> %lx (%d)\n",
			    (unsigned long)m[i].start,
			    m[i].orig_madv, m[i].new_madv, i);
			fail();
			return -1;
		}

	}

	pass();

	return 0;
}
