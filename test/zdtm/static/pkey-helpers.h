#ifndef ZDTM_STATIC_PKEY_HELPERS_H
#define ZDTM_STATIC_PKEY_HELPERS_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_pkey_mprotect
#define __NR_pkey_mprotect 329
#endif

#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc 330
#endif

#ifndef __NR_pkey_free
#define __NR_pkey_free 331
#endif

static inline int sys_pkey_mprotect(void *addr, size_t len, int prot, int pkey)
{
	return syscall(__NR_pkey_mprotect, addr, len, prot, pkey);
}

static inline int sys_pkey_alloc(unsigned int flags, unsigned int access_rights)
{
	return syscall(__NR_pkey_alloc, flags, access_rights);
}

static inline int sys_pkey_free(int pkey)
{
	return syscall(__NR_pkey_free, pkey);
}

static inline void free_pkeys(int *keys, size_t nr_keys)
{
	size_t i;

	for (i = 0; i < nr_keys; i++) {
		if (keys[i] >= 0)
			sys_pkey_free(keys[i]);
	}
}

static inline int read_vma_pkey(void *addr, int *pkey, bool *has_pkey)
{
	FILE *smaps;
	char line[1024];
	unsigned long target = (unsigned long)addr;
	bool in_vma = false;

	*pkey = 0;
	*has_pkey = false;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps)
		return -1;

	while (fgets(line, sizeof(line), smaps)) {
		unsigned long start, end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			in_vma = (start <= target && target < end);
			continue;
		}

		if (!in_vma)
			continue;

		if (!strncmp(line, "ProtectionKey:", 14)) {
			int v;

			if (sscanf(line + 14, "%d", &v) == 1) {
				*pkey = v;
				*has_pkey = true;
			}
			break;
		}
	}

	fclose(smaps);
	return 0;
}

#endif /* ZDTM_STATIC_PKEY_HELPERS_H */
