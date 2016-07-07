
#ifdef CONFIG_X86_64
static struct syscall_exec_desc sc_exec_table_64[] = {
#include "sys-exec-tbl-64.c"
	{ }, /* terminator */
};
#endif

static struct syscall_exec_desc sc_exec_table_32[] = {
#include "sys-exec-tbl-32.c"
	{ }, /* terminator */
};

struct syscall_exec_desc;

static inline struct syscall_exec_desc *
find_syscall_table(char *name, struct syscall_exec_desc *tbl)
{
	int i;

	for (i = 0; tbl[i].name != NULL; i++)
		if (!strcmp(tbl[i].name, name))
			return &tbl[i];
	return NULL;
}

#define ARCH_HAS_FIND_SYSCALL
/* overwrite default to search in two tables above */
#ifdef CONFIG_X86_64
struct syscall_exec_desc * find_syscall(char *name, struct parasite_ctl *ctl)
{
	if (seized_native(ctl))
		return find_syscall_table(name, sc_exec_table_64);
	else
		return find_syscall_table(name, sc_exec_table_32);
}
#else
struct syscall_exec_desc *
find_syscall(char *name, __always_unused struct parasite_ctl *ctl)
{
	return find_syscall_table(name, sc_exec_table_32);
}
#endif
