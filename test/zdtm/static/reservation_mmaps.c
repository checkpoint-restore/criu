#include <sys/mman.h>

#include "zdtmtst.h"
#include "get_smaps_bits.h"

#define SIZE (4UL * (1UL << 20)) /* 4MB */

const char *test_doc = "Check mmaps done for reserving virtual address space, do not have ac flag set in /proc/pid/smaps\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

static void check_ac_flag(char *buf, bool *no_ac)
{
	char *tok;

	if (!buf[0])
		return;

	*no_ac = true;
	tok = strtok(buf, " \n");
	if (!tok)
		return;

#define _vmflag_match(_t, _s) (_t[0] == _s[0] && _t[1] == _s[1])

	do {
		if (_vmflag_match(tok, "ac")) {
			*no_ac = false;
			return;
		}
		/*
		 * Anything else is just ignored.
		 */
	} while ((tok = strtok(NULL, " \n")));

#undef _vmflag_match
	return;
}

static int is_accountable(unsigned long where, bool *no_ac)
{
	unsigned long start = 0, end = 0;
	FILE *smaps = NULL;
	char buf[1024];
	int found = 0;

	if (!where)
		return 0;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps) {
		pr_perror("Can't open smaps");
		return -1;
	}

	while (fgets(buf, sizeof(buf), smaps)) {
		is_vma_range_fmt(buf, &start, &end);

		if (!strncmp(buf, "VmFlags: ", 9) && start <= where && where < end) {
			found = 1;
			check_ac_flag(buf, no_ac);
			break;
		}
	}

	fclose(smaps);

	if (!found) {
		pr_perror("VmFlags not found for %lx", where);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	uint32_t crc = ~0;
	uint8_t *data_mmap, *reservation_mmap;
	bool no_ac;

	test_init(argc, argv);
	data_mmap = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (data_mmap == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb memory", SIZE >> 20);
		return 1;
	}

	reservation_mmap = mmap(NULL, SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (reservation_mmap == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb memory", SIZE >> 20);
		return 1;
	}

	datagen(data_mmap, SIZE, &crc);

	if (mprotect(data_mmap, SIZE, PROT_NONE)) {
		pr_perror("Failed to set protections on %p", data_mmap);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * check that a mmap whose memory protection got changed
	 * to PROT_NONE still has the data stored in it.
	 */
	if (mprotect(data_mmap, SIZE, PROT_READ)) {
		pr_perror("Failed to set protections on %p", data_mmap);
		return 1;
	}

	crc = ~0;
	if (datachk(data_mmap, SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}

	/* reservation_mmap should not have ac flag set in /proc/pid/smaps */
	if (is_accountable((unsigned long)reservation_mmap, &no_ac)) {
		fail("could not check for no ac flag on reservation mmap");
		return 1;
	}

	if (!no_ac) {
		fail("reservation mmap has ac flag set");
		return 1;
	}

	pass();
	return 0;
}
