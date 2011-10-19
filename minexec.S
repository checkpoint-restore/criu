#include "syscal-codes.h"

#define SIGSTOP			19

	.code64

	.global _start
_start:
1:
	/*
	 * Simply put self into stopped state,
	 * the restorer will resume us anyway.
	 */
	movl	$__NR_getpid, %eax
	syscall
	movl	%eax, %edi
	movl	$__NR_kill, %eax
	movl	$SIGSTOP, %esi
	syscall
	jmp 1b
