#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

/*
 * The parasite is started from the lowest executable VMA: its syscall
 * instruction is written there with ptrace and the original bytes are put
 * back afterwards. That VMA must be private. A shared one either cannot be
 * written that way (read-only: the dump fails) or has the injected code
 * written through to the file (writable).
 *
 * Put a shared executable mapping below every other executable VMA, as
 * 32-bit Wine does with its NLS files, and check that dump and restore
 * leave it alone. Variants:
 *   maps_shared_exec       read-only shared file mapping
 *   maps_shared_exec_anon  read-only shared anonymous mapping
 *   maps_shared_exec_rw    writable shared file mapping; a write through it
 *                          updates the file's mtime, even if undone later
 */

#if defined(SHARED_ANON)
const char *test_doc = "Check dump when the lowest executable VMA is shared anonymous memory";
#elif defined(SHARED_RW)
const char *test_doc = "Check that dump does not write into a lowest executable writable shared file mapping";
#else
const char *test_doc = "Check dump when the lowest executable VMA is a shared read-only file mapping";
#endif
const char *test_author = "Tom Fairfield <tom@fairfieldt.com>";

#ifndef SHARED_ANON
char *filename;
TEST_OPTION(filename, string, "file name", 1);
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Start of the lowest executable mapping, and whether it is shared. */
static int lowest_exec(unsigned long *start, int *shared)
{
	unsigned long end;
	char line[512], perms[5];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		pr_perror("Can't open /proc/self/maps");
		return -1;
	}

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", start, &end, perms) != 3)
			continue;
		if (perms[2] != 'x')
			continue;
		*shared = perms[3] == 's';
		fclose(maps);
		return 0;
	}

	fclose(maps);
	pr_err("No executable mapping found\n");
	return -1;
}

static unsigned long mmap_min_addr(void)
{
	unsigned long value = 65536;
	FILE *f;

	f = fopen("/proc/sys/vm/mmap_min_addr", "r");
	if (f) {
		if (fscanf(f, "%lu", &value) != 1)
			value = 65536;
		fclose(f);
	}
	return value;
}

/*
 * Map one page directly below the lowest executable VMA. Returns NULL when
 * this address space has no room there, e.g. a non-PIE program loaded at
 * mmap_min_addr.
 */
static void *map_below_exec(int prot, int flags, int fd)
{
	unsigned long lowest, floor = mmap_min_addr(), addr;
	int shared, tries;
	void *map;

	if (lowest_exec(&lowest, &shared))
		return MAP_FAILED;

	addr = lowest - PAGE_SIZE;
	for (tries = 0; tries < 64 && addr >= floor && addr < lowest; tries++, addr -= PAGE_SIZE) {
		map = mmap((void *)addr, PAGE_SIZE, prot, flags | MAP_FIXED_NOREPLACE, fd, 0);
		if (map == MAP_FAILED) {
			if (errno == EEXIST)
				continue;
			pr_perror("Can't map a page at %#lx", addr);
			return MAP_FAILED;
		}
		if (map == (void *)addr)
			return map;
		/* A kernel without MAP_FIXED_NOREPLACE treats addr as a hint. */
		munmap(map, PAGE_SIZE);
	}
	return NULL;
}

static int check_layout(void *map)
{
	unsigned long lowest;
	int shared;

	if (lowest_exec(&lowest, &shared))
		return -1;
	return lowest == (unsigned long)map && shared ? 0 : 1;
}

int main(int argc, char **argv)
{
	unsigned char *pattern;
	void *map;
	int i;
#ifndef SHARED_ANON
	unsigned char *check;
	int fd;
	struct stat before, after;
#endif

	test_init(argc, argv);

	pattern = malloc(PAGE_SIZE);
	if (!pattern) {
		pr_perror("malloc");
		return 1;
	}
	for (i = 0; i < PAGE_SIZE; i++)
		pattern[i] = i * 7 + 1;

#ifdef SHARED_ANON
	map = map_below_exec(PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1);
	if (map && map != MAP_FAILED) {
		memcpy(map, pattern, PAGE_SIZE);
		if (mprotect(map, PAGE_SIZE, PROT_READ | PROT_EXEC)) {
			pr_perror("mprotect");
			return 1;
		}
	}
#else
	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", filename);
		return 1;
	}
	if (write(fd, pattern, PAGE_SIZE) != PAGE_SIZE) {
		pr_perror("Can't write %s", filename);
		return 1;
	}
#ifdef SHARED_RW
	/*
	 * Never write through the mapping: its pages must stay clean, so that
	 * any later write faults and updates the file times.
	 */
	map = map_below_exec(PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd);
#else
	close(fd);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
		return 1;
	}
	map = map_below_exec(PROT_READ | PROT_EXEC, MAP_SHARED, fd);
#endif
	close(fd);
#endif

	if (map == MAP_FAILED)
		return 1;
	if (!map) {
		skip("No room for a mapping below the lowest executable VMA");
		test_daemon();
		test_waitsig();
		pass();
		return 0;
	}
	if (check_layout(map)) {
		pr_err("The shared mapping at %p is not the lowest executable VMA\n", map);
		return 1;
	}
	if (memcmp(map, pattern, PAGE_SIZE)) {
		pr_err("Mapping does not show the expected content\n");
		return 1;
	}
#ifndef SHARED_ANON
	if (stat(filename, &before)) {
		pr_perror("Can't stat %s", filename);
		return 1;
	}
#endif

	test_daemon();
	test_waitsig();

	if (check_layout(map)) {
		fail("The shared executable mapping was not restored as the lowest executable VMA");
		return 1;
	}
	if (memcmp(map, pattern, PAGE_SIZE)) {
		fail("Mapping content changed");
		return 1;
	}

#ifndef SHARED_ANON
	if (stat(filename, &after)) {
		fail("Can't stat %s", filename);
		return 1;
	}
	if (before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
	    before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
		fail("%s was modified through the mapping", filename);
		return 1;
	}
	check = malloc(PAGE_SIZE);
	fd = open(filename, O_RDONLY);
	if (!check || fd < 0 || read(fd, check, PAGE_SIZE) != PAGE_SIZE) {
		fail("Can't read back %s", filename);
		return 1;
	}
	close(fd);
	if (memcmp(check, pattern, PAGE_SIZE)) {
		fail("File content changed");
		return 1;
	}
#endif

	pass();
	return 0;
}
