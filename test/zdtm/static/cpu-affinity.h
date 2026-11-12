#ifndef __CPU_AFFINITY_H__
#define __CPU_AFFINITY_H__

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Allocate a CPU set large enough for this host and fill it with the
 * affinity of @pid (0 for the calling process).  Grow the mask on
 * EINVAL to exceed the CPU_SETSIZE (1024) limit.
 *
 * @size is set to the allocated size in bytes.
 * Returns the allocated set on success, NULL on failure.
 * The returned set must be released with CPU_FREE().
 */
static inline cpu_set_t *affinity_alloc(pid_t pid, size_t *size)
{
	size_t nr_cpus = CPU_SETSIZE;
	cpu_set_t *set = NULL;
	int affinity_errno;
	long conf;

	conf = sysconf(_SC_NPROCESSORS_CONF);
	if (conf > (long)nr_cpus)
		nr_cpus = (size_t)conf;

	for (;;) {
		set = CPU_ALLOC(nr_cpus);
		if (!set)
			goto out;
		*size = CPU_ALLOC_SIZE(nr_cpus);
		CPU_ZERO_S(*size, set);
		if (sched_getaffinity(pid, *size, set) == 0)
			goto out;
		affinity_errno = errno;
		CPU_FREE(set);
		set = NULL;
		if (affinity_errno != EINVAL)
			goto out;
		if (nr_cpus > (size_t)INT_MAX / 2)
			goto out;
		nr_cpus *= 2;
	}

out:
	return set;
}

static inline int affinity_first_cpu(size_t size, const cpu_set_t *set)
{
	int cpu;

	for (cpu = 0; cpu < (int)(size * 8); cpu++)
		if (CPU_ISSET_S(cpu, size, set))
			return cpu;

	return -1;
}

#endif /* __CPU_AFFINITY_H__ */
