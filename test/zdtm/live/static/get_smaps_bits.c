#include <string.h>
#include <sys/mman.h>
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

int get_smaps_bits(unsigned long where, unsigned long *flags, unsigned long *madv)
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
