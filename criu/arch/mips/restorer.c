#include <unistd.h>

#include "types.h"
#include "restorer.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall-codes.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/syscall.h>
#include "log.h"
#include "cpu.h"

int restore_nonsigframe_gpregs(UserMipsRegsEntry *r)
{
    return 0;
}
