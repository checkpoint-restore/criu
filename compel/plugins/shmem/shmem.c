#include <sys/mman.h>

#include <compel/plugins.h>
#include <compel/plugins/shmem.h>
#include <compel/plugins/std/syscall.h>
#include "shmem.h"
#include "std-priv.h"

void *shmem_create(unsigned long size)
{
	int ret;
	void *mem;
	struct shmem_plugin_msg spi;

	mem = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (mem == MAP_FAILED)
		return NULL;

	spi.start = (unsigned long)mem;
	spi.len = size;

	ret = sys_write(std_ctl_sock(), &spi, sizeof(spi));
	if (ret != sizeof(spi)) {
		sys_munmap(mem, size);
		return NULL;
	}

	return mem;
}

void *shmem_receive(unsigned long *size)
{
	/* master -> parasite not implemented yet */
	return NULL;
}

PLUGIN_REGISTER_DUMMY(shmem)
