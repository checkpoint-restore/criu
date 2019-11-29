#include "common/asm/linkage.h"
/*	
#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	daddiu	sp,sp,-8;		\
	sd	s8,0(sp);		\
	move	s8,sp;			\
	move s0, a0;			\
	move a0, a1;			\
	move a1, a2;			\
	move a2, a3;			\
	move a3, a4;			\
	move a4, a5;			\
	move v0, s0;			\
	syscall;			\
	move	sp,s8;			\
	ld	s8,0(sp);		\
	daddiu	sp,sp,8;		\
	jr ra;				\
	nop;				\
	END(name)
*/
#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	li v0, opcode;		\
	syscall;			\
	jr ra;				\
	nop;				\
	END(name)
	
	.text
	.align	4


ENTRY(__cr_restore_rt)
	li v0,__NR_rt_sigreturn
	syscall
END(__cr_restore_rt)
