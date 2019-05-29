#include <compel/plugins/std/syscall.h>

/* That's __builtin___clear_cache() to flush CPU cache */
void __clear_cache(void *start, void *end)
{
	sys_cacheflush(start, end, 0);
}
