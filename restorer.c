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

	}

	asm volatile(".align "__stringify(RESTORER_SIZE));

	return ret;
}
