#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include "asm/fpu.h"

#include "syscall.h"
#include "log.h"
//#include "cpu.h"

int restore_nonsigframe_gpregs(UserPpc64RegsEntry *r)
{
	return 0;
}
