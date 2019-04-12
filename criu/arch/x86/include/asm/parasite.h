#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall-codes.h>
#include "asm/compat.h"

static int arch_get_user_desc(user_desc_t *desc)
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
	"	mov %0,%%eax			\n"
	"	mov %1,%%rbx			\n"
	"	int $0x80			\n"
	"	mov %%eax,%0			\n"
	: "+m"(ret)
	: "m"(desc)
	: "rax", "rbx", "r8", "r9", "r10", "r11", "memory");

	if (ret)
		pr_err("Failed to dump TLS descriptor #%d: %d\n",
				desc->entry_number, ret);
	return ret;
}

static void arch_get_tls(tls_t *ptls)
{
	void *syscall_mem;
	int i;

	syscall_mem = alloc_compat_syscall_stack();
	if (!syscall_mem) {
		pr_err("Failed to allocate memory <4Gb for compat syscall\n");

		for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
			user_desc_t *d = &ptls->desc[i];

			d->seg_not_present = 1;
			d->entry_number = GDT_ENTRY_TLS_MIN + i;
		}
		return;
	}

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++)
	{
		user_desc_t *d = syscall_mem;

		memset(d, 0, sizeof(user_desc_t));
		d->seg_not_present = 1;
		d->entry_number = GDT_ENTRY_TLS_MIN + i;
		arch_get_user_desc(d);
		memcpy(&ptls->desc[i], d, sizeof(user_desc_t));
	}

	free_compat_syscall_stack(syscall_mem);
}

#endif
