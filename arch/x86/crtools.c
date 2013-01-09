#include <string.h>
#include <unistd.h>

#include "asm/types.h"
#include "compiler.h"
#include "ptrace.h"
#include "asm/processor-flags.h"
#include "protobuf.h"
#include "../protobuf/core.pb-c.h"
#include "../protobuf/creds.pb-c.h"
#include "parasite-syscall.h"
#include "syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "fpu.h"
#include "elf.h"
#include "parasite-syscall.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x0f, 0x05,				/* syscall    */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
};

const int code_syscall_size = round_up(sizeof(code_syscall), sizeof(long));

static inline void __check_code_syscall(void)
{
	BUILD_BUG_ON(sizeof(code_syscall) != BUILTIN_SYSCALL_SIZE);
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));
}

void parasite_setup_regs(unsigned long new_ip, user_regs_struct_t *regs)
{
	regs->ip = new_ip;

	/* Avoid end of syscall processing */
	regs->orig_ax = -1;

	/* Make sure flags are in known state */
	regs->flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF);
}
