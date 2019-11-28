/*fixme: gysun */
//#include <asm/prctl.h>
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
#if 0 //fixme: gysun
int arch_map_vdso(unsigned long map_at, bool compatible)
{

	int vdso_type = compatible ? ARCH_MAP_VDSO_32 : ARCH_MAP_VDSO_64;

	pr_debug("Mapping %s vDSO at %lx\n",
		compatible ? "compatible" : "native", map_at);

	return sys_arch_prctl(vdso_type, map_at);

	return 0;
}
#endif
int restore_nonsigframe_gpregs(UserMipsRegsEntry *r)
{
	return 0;
#if 0 //fixme: gysun
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
#endif
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
    pr_warn("-ERROR:MIPS 未实现 %s %d restore_tls\n",__FILE__,__LINE__);
}
#endif
