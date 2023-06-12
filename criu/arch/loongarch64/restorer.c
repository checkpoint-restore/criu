#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall.h>
#include "log.h"
#include "cpu.h"

int restore_nonsigframe_gpregs(UserLoongarch64GpregsEntry *r)
{
	return 0;
}
