#include <asm/prctl.h>
#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include "asm/fpu.h"

#include "syscall.h"
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
