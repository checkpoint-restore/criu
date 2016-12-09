#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

#include "asm-generic/string.h"
#include <compel/plugins/std/syscall-codes.h>

#ifdef CONFIG_X86_32
# define __parasite_entry __attribute__((regparm(3)))
#endif

static void arch_get_user_desc(user_desc_t *desc)
{
	int ret = __NR32_get_thread_area;
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
	 */
	asm volatile (
	"       mov %0,%%eax                    \n"
	"       mov %1,%%rbx                    \n"
	"	int $0x80			\n"
	"	mov %%eax,%0			\n"
	: "+m"(ret)
	: "m"(desc)
	: "eax", "rbx", "memory");

	/*
	 * Fixup for Travis: on missing GDT entry get_thread_area()
	 * retruns -EINTR then descriptor with seg_not_preset = 1
	 */
	if (ret)
		pr_err("Failed to dump TLS descriptor #%d: %d\n",
				desc->entry_number, ret);
}

static void arch_get_tls(tls_t *ptls)
{
	int i;

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++)
	{
		user_desc_t *d = &ptls->desc[i];

		builtin_memset(d, 0, sizeof(user_desc_t));
		d->seg_not_present = 1;
		d->entry_number = GDT_ENTRY_TLS_MIN + i;
		arch_get_user_desc(d);
	}
}

#endif
