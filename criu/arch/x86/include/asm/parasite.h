#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

#include "asm-generic/string.h"

#ifdef CONFIG_X86_32
# define __parasite_entry __attribute__((regparm(3)))
#endif

#ifdef CONFIG_X86_32
static void arch_get_user_desc(user_desc_t *desc)
{
	if (sys_get_thread_area(desc))
		pr_err("Failed to dump TLS descriptor #%d\n",
				desc->entry_number);
}
#else /* !X86_32 */
static void arch_get_user_desc(user_desc_t *desc)
{
	/*
	 * For 64-bit applications, TLS (fs_base for Glibc) is
	 * in MSR, which are dumped with the help of arch_prctl().
	 *
	 * But SET_FS_BASE will update GDT if base pointer fits in 4 bytes.
	 * Otherwise it will set only MSR, which allows for mixed 64/32-bit
	 * code to use: 2 MSRs as TLS base _and_ 3 GDT entries.
	 * Having in sum 5 TLS pointers, 3 of which are four bytes and
	 * other two bigger than four bytes:
	 * struct thread_struct {
	 *	struct desc_struct	tls_array[3];
	 *	...
	 * #ifdef CONFIG_X86_64
	 *	unsigned long		fsbase;
	 *	unsigned long		gsbase;
	 * #endif
	 *	...
	 * };
	 *
	 * For this mixed code we may want to call get_thread_area
	 * 32-bit syscall. But as additional three calls to kernel
	 * will slow dumping, I omit it here.
	 */
	desc->seg_not_present = 1;
}
#endif /* !X86_32 */

static void arch_get_tls(tls_t *ptls)
{
	int i;

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++)
	{
		user_desc_t *d = &ptls->desc[i];

		builtin_memset(d, 0, sizeof(user_desc_t));
		d->entry_number = GDT_ENTRY_TLS_MIN + i;
		arch_get_user_desc(d);
	}
}

#endif
