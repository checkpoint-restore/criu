#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "util.h"
#include "image.h"

#include "crtools.h"
#include "restorer.h"

#define get_rt_sigframe_addr(stack)					\
	(struct rt_sigframe *)(stack - sizeof(long))

#define lea_args_off(p)							\
	do {								\
		asm volatile(						\
			"leaq restore_args__(%%rip), %%rax	\n\t"	\
			"movq %%rax, %0				\n\t"	\
			: "=m"(p)					\
			:						\
			: "memory");					\
	} while (0)

static void always_inline write_string(char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(1, str, len);
}

long restorer(long cmd)
{
	long ret = -1;

	asm volatile(
		"jmp 1f						\n\t"
		"restore_args__:				\n\t"
		".skip "__stringify(RESTORER_ARGS_SIZE)",0	\n\t"
		"1:						\n\t"
		:
		:
		: "memory");

	switch (cmd) {
	case RESTORER_CMD__PR_ARG_STRING:
	{
		char *str = NULL;

		lea_args_off(str);
		write_string(str);

		ret = 0;
	}
		break;

	case RESTORER_CMD__GET_ARG_OFFSET:
		lea_args_off(ret);
		break;

	case RESTORER_CMD__GET_SELF_LEN:
		goto self_len_start;
self_len_end:
		break;

	/*
	 * This one is very special, we never return there
	 * but use sigreturn facility to restore core registers
	 * and jump execution to some predefined ip read from
	 * core file.
	 */
	case RESTORER_CMD__RESTORE_CORE:
	{
		struct restore_core_args *args;
		int fd_core;

		struct core_entry core_entry;
		struct vma_entry vma_entry;
		u64 va;

		struct rt_sigframe *frame;

		lea_args_off(args);

		write_string(args->core_path);
		write_string("\n");

		write_string(args->self_vmas_path);
		write_string("\n");

		fd_core = sys_open(args->core_path, O_RDONLY, CR_FD_PERM);
		if (fd_core < 0)
			return fd_core;

		sys_lseek(fd_core, MAGIC_OFFSET, SEEK_SET);
		ret = sys_read(fd_core, &core_entry, sizeof(core_entry));

		sys_close(fd_core);
		if (ret != sizeof(core_entry))
			return -ret;

		sys_exit(0);
		return ret;

		/*
		 * Unmap all but self, note that we reply on
		 * caller that it has placed this execution
		 * code at the VMA which we can keep mapped.
		 */

		/*
		 * Map VMAs we will need.
		 */

		/*
		 * Threads here with registers and pids
		 * we need.
		 */

		/*
		 * Setup a sigreturn frame.
		 */

		/* Finally call for sigreturn */
		sys_rt_sigreturn();
	}
		break;

	default:
		ret = -1;
		break;
	}

	return ret;

self_len_start:
	asm volatile(
		".align 16				\t\n"
		"self:					\t\n"
		"leaq self(%%rip), %%rax		\t\n"
		"movq %%rax, %0				\t\n"
		: "=r"(ret)
		:
		: "memory");
	goto self_len_end;
}
