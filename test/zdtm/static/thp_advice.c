#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "zdtmtst.h"
#include "get_smaps_bits.h"

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

const char *test_doc = "Check that restored memory is backed by the page size its THP advice asks for";
const char *test_author = "Partha P.G. <yes.par781@gmail.com>";

/* Larger PMD sizes (e.g. 512M with 64K pages) make the test too heavy */
#define MAX_PMD_SIZE (32UL << 20)

static unsigned long pmd_size(void)
{
	unsigned long size = 0;
	FILE *f;

	f = fopen("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");
	if (!f)
		return 0;
	if (fscanf(f, "%lu", &size) != 1)
		size = 0;
	fclose(f);
	return size;
}

/*
 * Map an area at @offset bytes past an @align boundary, with unmapped guard
 * pages on both sides so adjacent test VMAs with identical advice never merge.
 */
static void *map_area(unsigned long size, unsigned long align,
		      unsigned long offset, int advice)
{
	unsigned long total = size + align + offset + 2 * PAGE_SIZE;
	unsigned long head, tail;
	char *raw, *area;

	raw = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED) {
		pr_perror("mmap failed");
		return NULL;
	}

	area = (char *)(((unsigned long)raw + PAGE_SIZE + align - 1) & ~(align - 1)) + offset;
	head = area - raw;
	tail = total - head - size;
	if (head && munmap(raw, head)) {
		pr_perror("munmap head failed");
		return NULL;
	}
	if (tail && munmap(area + size, tail)) {
		pr_perror("munmap tail failed");
		return NULL;
	}

	if (madvise(area, size, advice)) {
		pr_perror("madvise(%d) failed", advice);
		return NULL;
	}

	return area;
}

/* Return AnonHugePages in kB for the VMA holding @addr, or -1 on error */
static long anon_huge_kb(void *addr)
{
	unsigned long start, end, a = (unsigned long)addr;
	char line[512];
	bool in_vma = false;
	long kb = -1;
	FILE *f;

	f = fopen("/proc/self/smaps", "r");
	if (!f) {
		pr_perror("Can't open smaps");
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx ", &start, &end) == 2) {
			in_vma = a >= start && a < end;
			continue;
		}
		if (in_vma && sscanf(line, "AnonHugePages: %ld kB", &kb) == 1)
			break;
	}

	fclose(f);
	if (kb < 0)
		pr_err("No AnonHugePages for %p\n", addr);
	return kb;
}

static int check_madv(void *addr, unsigned long want)
{
	unsigned long flags = 0, madv = 0;

	if (get_smaps_bits((unsigned long)addr, &flags, &madv))
		return -1;
	if (!(madv & want)) {
		fail("Advice %lx lost on %p (madv %lx)", want, addr, madv);
		return -1;
	}
	return 0;
}

/*
 * Check one restored area. Returns 0 on success. On failure, the reason is
 * reported and 1 is returned.
 */
static int check_area(const char *name, uint8_t *area, unsigned long size,
		      uint32_t init_crc, uint32_t want_crc,
		      unsigned long want_madv, long huge_before,
		      bool expect_huge)
{
	uint32_t crc = init_crc;
	long huge_after;

	if (datachk(area, size, &crc) || crc != want_crc) {
		fail("%s: memory contents changed", name);
		return 1;
	}

	if (check_madv(area, want_madv))
		return 1;

	huge_after = anon_huge_kb(area);
	if (huge_after < 0)
		return 1;
	test_msg("%s AnonHugePages after restore: %ld kB\n", name, huge_after);

	if (!expect_huge && huge_after) {
		fail("%s: MADV_NOHUGEPAGE area restored with %ld kB of huge pages",
		     name, huge_after);
		return 1;
	}

	if (expect_huge && huge_before && !huge_after) {
		fail("%s: MADV_HUGEPAGE area restored without huge pages (%ld kB before dump)",
		     name, huge_before);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned long pmd, align, size, unaligned_off, unaligned_size;
	uint32_t crc_huge = ~0U, crc_unaligned = ~0U, crc_base = ~0U;
	long huge_before, unaligned_before;
	uint8_t *huge, *huge_unaligned, *base;
#ifdef THP_COW
	uint32_t crc_conflict = ~0U;
	long conflict_before;
	uint8_t *conflict;
	int sync_fd[2];
	char ready = 1;
	int status;
	pid_t pid;
#endif

	test_init(argc, argv);

	pmd = pmd_size();
	if (pmd > MAX_PMD_SIZE)
		pmd = 0;
	align = pmd ?: PAGE_SIZE;
	size = pmd ? 2 * pmd : (4UL << 20);
	unaligned_off = pmd ? pmd - PAGE_SIZE : 0;
	unaligned_size = size + (pmd ? 2 * PAGE_SIZE : 0);

	huge = map_area(size, align, 0, MADV_HUGEPAGE);
	huge_unaligned = map_area(unaligned_size, align, unaligned_off, MADV_HUGEPAGE);
	base = map_area(size, align, 0, MADV_NOHUGEPAGE);
	if (!huge || !huge_unaligned || !base)
		return 1;

	datagen(huge, size, &crc_huge);
	datagen(huge_unaligned, unaligned_size, &crc_unaligned);
	datagen(base, size, &crc_base);

	/*
	 * Huge pages may be unavailable here, e.g. with THP set to "never" or
	 * when memory is too fragmented. Only expect them after restore if the
	 * kernel gave them before the dump.
	 */
	huge_before = anon_huge_kb(huge);
	unaligned_before = anon_huge_kb(huge_unaligned);
	if (huge_before < 0 || unaligned_before < 0 || anon_huge_kb(base) < 0)
		return 1;
	test_msg("AnonHugePages before dump: aligned=%ld kB, unaligned=%ld kB\n",
		 huge_before, unaligned_before);

#ifdef THP_COW
	conflict = map_area(size, align, 0, MADV_HUGEPAGE);
	if (!conflict)
		return 1;
	datagen(conflict, size, &crc_conflict);
	conflict_before = anon_huge_kb(conflict);
	if (conflict_before < 0)
		return 1;

	if (pipe(sync_fd)) {
		pr_perror("pipe failed");
		return 1;
	}

	/*
	 * The child shares huge, huge_unaligned, and base copy-on-write, while
	 * switching conflict to MADV_NOHUGEPAGE and replacing its pages so
	 * parent and child require independent premappings.
	 */
	pid = test_fork();
	if (pid < 0) {
		pr_perror("Unable to fork a new process");
		close(sync_fd[0]);
		close(sync_fd[1]);
		return 1;
	}
	if (pid == 0) {
		uint32_t crc_conflict_child = ~1U;

		close(sync_fd[0]);

		if (madvise(conflict, size, MADV_NOHUGEPAGE)) {
			pr_perror("Child madvise(MADV_NOHUGEPAGE) failed");
			return 1;
		}
		if (madvise(conflict, size, MADV_DONTNEED)) {
			pr_perror("Child madvise(MADV_DONTNEED) failed");
			return 1;
		}
		datagen(conflict, size, &crc_conflict_child);
		if (anon_huge_kb(conflict) != 0) {
			fail("Child MADV_NOHUGEPAGE area has huge pages before dump");
			return 1;
		}

		if (TEMP_FAILURE_RETRY(write(sync_fd[1], &ready, 1)) != 1) {
			pr_perror("Child sync write failed");
			return 1;
		}
		close(sync_fd[1]);

		test_waitsig();
		if (check_area("child huge", huge, size, ~0U, crc_huge,
			       1UL << MADV_HUGEPAGE, huge_before, true) ||
		    check_area("child huge_unaligned", huge_unaligned, unaligned_size,
			       ~0U, crc_unaligned, 1UL << MADV_HUGEPAGE,
			       unaligned_before, true) ||
		    check_area("child base", base, size, ~0U, crc_base,
			       1UL << MADV_NOHUGEPAGE, 0, false) ||
		    check_area("child conflict", conflict, size, ~1U,
			       crc_conflict_child, 1UL << MADV_NOHUGEPAGE,
			       0, false))
			return 1;
		return 0;
	}

	close(sync_fd[1]);
	if (TEMP_FAILURE_RETRY(read(sync_fd[0], &ready, 1)) != 1) {
		close(sync_fd[0]);
		if (waitpid(pid, &status, 0) != pid)
			pr_perror("Unable to wait for failed child %d", pid);
		else
			fail("Child setup failed: status %x", status);
		return 1;
	}
	close(sync_fd[0]);
#endif

	test_daemon();
	test_waitsig();

#ifdef THP_COW
	kill(pid, SIGTERM);
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait for the child %d", pid);
		return 1;
	}
#endif

	if (check_area("huge", huge, size, ~0U, crc_huge,
		       1UL << MADV_HUGEPAGE, huge_before, true) ||
	    check_area("huge_unaligned", huge_unaligned, unaligned_size,
		       ~0U, crc_unaligned, 1UL << MADV_HUGEPAGE,
		       unaligned_before, true) ||
	    check_area("base", base, size, ~0U, crc_base,
		       1UL << MADV_NOHUGEPAGE, 0, false))
		return 1;

#ifdef THP_COW
	if (check_area("parent conflict", conflict, size, ~0U, crc_conflict,
		       1UL << MADV_HUGEPAGE, conflict_before, true))
		return 1;

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("The child failed: status %x", status);
		return 1;
	}
#endif

	pass();
	return 0;
}
