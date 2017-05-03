#include <asm/prctl.h>
#include <unistd.h>

#include "types.h"
#include "restorer.h"
#include "asm/compat.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "log.h"
#include "cpu.h"

int restore_nonsigframe_gpregs(UserX86RegsEntry *r)
{
	long ret;
	unsigned long fsgs_base;

	fsgs_base = r->fs_base;
	ret = sys_arch_prctl(ARCH_SET_FS, fsgs_base);
	if (ret) {
		pr_info("SET_FS fail %ld\n", ret);
		return -1;
	}

	fsgs_base = r->gs_base;
	ret = sys_arch_prctl(ARCH_SET_GS, fsgs_base);
	if (ret) {
		pr_info("SET_GS fail %ld\n", ret);
		return -1;
	}
	return 0;
}

#ifdef CONFIG_COMPAT

int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	struct syscall_args32 s = {
		.nr	= __NR32_set_robust_list,
		.arg0	= head_ptr,
		.arg1	= len,
	};

	do_full_int80(&s);
	return (int)s.nr;
}

static int prepare_stack32(void **stack32)
{
	if (*stack32)
		return 0;

	*stack32 = alloc_compat_syscall_stack();
	if (!*stack32) {
		pr_err("Failed to allocate stack for 32-bit TLS restore\n");
		return -1;
	}

	return 0;
}

void restore_tls(tls_t *ptls)
{
	/*
	 * We need here compatible stack, because 32-bit syscalls get
	 * 4-byte pointer and _usally_ restorer is also under 4Gb, but
	 * it can be upper and then pointers are messed up.
	 * (we lose high 4 bytes and... BANG!)
	 * Nothing serious, but syscall will return -EFAULT - or if we're
	 * lucky and lower 4 bytes points on some writeable VMA - corruption).
	 */
	void *stack32 = NULL;
	unsigned i;

	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		user_desc_t *desc = &ptls->desc[i];
		int ret;

		if (desc->seg_not_present)
			continue;

		if (prepare_stack32(&stack32) < 0)
			return;

		memcpy(stack32, desc, sizeof(user_desc_t));
		asm volatile (
		"       mov %1,%%eax			\n"
		"       mov %2,%%ebx			\n"
		"	int $0x80			\n"
		"	mov %%eax,%0			\n"
		: "=g"(ret)
		: "r"(__NR32_set_thread_area), "r"((uint32_t)(uintptr_t)stack32)
		: "eax", "ebx", "r8", "r9", "r10", "r11", "memory");

		if (ret)
			pr_err("Failed to restore TLS descriptor %u in GDT: %d\n",
					desc->entry_number, ret);
	}

	if (stack32)
		free_compat_syscall_stack(stack32);
}
#endif
