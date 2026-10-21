#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/*
 * Map a shared, read-only, executable page directly below the lowest
 * executable VMA, so that it is the first executable area in /proc/self/maps.
 * Reports 1 on stdout when that layout exists, 0 when there is no room for
 * it, then answers every read on stdin with its pid.
 */
static void *map_below_exec(long page)
{
	unsigned long start = 0, end, floor = 65536, addr;
	char line[512], perms[5];
	FILE *f;
	void *map;
	int fd, i;

	f = fopen("/proc/sys/vm/mmap_min_addr", "r");
	if (f) {
		if (fscanf(f, "%lu", &floor) != 1)
			floor = 65536;
		fclose(f);
	}

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return NULL;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3 && perms[2] == 'x')
			break;
	fclose(f);

	fd = memfd_create("shexec", 0);
	if (fd < 0 || ftruncate(fd, page))
		return NULL;

	addr = start - page;
	for (i = 0; i < 64 && addr >= floor && addr < start; i++, addr -= page) {
		map = mmap((void *)addr, page, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
		if (map == (void *)addr)
			return map;
		if (map != MAP_FAILED)
			munmap(map, page);
		else if (errno != EEXIST)
			break;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int i, ready = map_below_exec(sysconf(_SC_PAGESIZE)) != NULL;

	if (write(1, &ready, sizeof(ready)) != sizeof(ready))
		return 1;

	while (1) {
		if (read(0, &i, sizeof(i)) != sizeof(i))
			break;

		i = getpid();
		if (write(1, &i, sizeof(i)) != sizeof(i))
			break;
	}

	return 0;
}
