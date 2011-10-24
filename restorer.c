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

#include "restorer.h"

long restorer(long cmd)
{
	long ret;

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
		int size = 0;

		asm volatile(
			"leaq restore_args__(%%rip), %%rax	\n\t"
			"movq %%rax, %0				\n\t"
			: "=m"(str)
			:
			: "memory");

		while (str[size])
			size++;
		sys_write(1, str, size);
	}
		break;

	case RESTORER_CMD__GET_ARG_OFFSET:
		asm volatile(
			"leaq restore_args__(%%rip), %%rax	\n\t"
			"movq %%rax, %0				\n\t"
			: "=m"(ret)
			:
			: "memory");
		break;

	/*
	 * This one is very special, we never return there
	 * but use sigreturn facility to restore core registers
	 * and jump execution to some predefined ip read from
	 * core file.
	 */
	case RESTORER_CMD__RESTORE_CORE:
	{
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

	asm volatile(".align "__stringify(RESTORER_SIZE));

	return ret;
}
