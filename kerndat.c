#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "log.h"
#include "kerndat.h"
#include "asm/types.h"

dev_t kerndat_shmem_dev;

/*
 * Anonymous shared mappings are backed by hidden tmpfs
 * mount. Find out its dev to distinguish such mappings
 * from real tmpfs files maps.
 */

static int kerndat_get_shmemdev(void)
{
	void *map;
	char maps[128];
	struct stat buf;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap piggie");
		return -1;
	}

	sprintf(maps, "/proc/self/map_files/%lx-%lx",
			(unsigned long)map, (unsigned long)map + PAGE_SIZE);
	if (stat(maps, &buf) < 0) {
		pr_perror("Can't stat piggie");
		return -1;
	}

	munmap(map, PAGE_SIZE);

	kerndat_shmem_dev = buf.st_dev;
	pr_info("Found anon-shmem piggie at %"PRIx64"\n", kerndat_shmem_dev);
	return 0;
}

int kerndat_init(void)
{
	int ret;

	ret = kerndat_get_shmemdev();

	return ret;
}
