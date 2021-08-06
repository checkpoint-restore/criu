#include <unistd.h>

#include "asm/restorer.h"
#include "restorer.h"

#include "cpu.h"
#include "log.h"
#include <compel/asm/fpu.h>
#include <compel/plugins/std/syscall.h>

int restore_nonsigframe_gpregs(UserRegsEntry *r)
{
	return 0;
}
