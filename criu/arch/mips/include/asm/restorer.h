#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include <compel/asm/fpu.h>
#include "images/core.pb-c.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/sigframe.h>

static inline void restore_tls(tls_t *ptls) { 
	asm volatile(							
		     "move $4, %0				    \n"	
		     "li $2,  "__stringify(__NR_set_thread_area)"  \n" 
		     "syscall					    \n"	
		     :							
		     : "r"(*ptls)					
		     : "$4","$2","memory");
}
static inline int arch_compat_rt_sigaction(void *stack, int sig, void *act)
{
	return -1;
}
static inline int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	return -1;
}

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)      \
    asm volatile(						 \
		 "ld    $5,%2	\n"	/* a1 = new_sp */	 \
		 "dsubu $5,32	\n"				 \
		 "sd    %5,0($5)	\n"				 \
		 "sd    %6,8($5)	\n"			 \
		 "sd    %1,16($5)   \n"				\
		 "move  $4,%1	\n"  /* a0=flags */			\
		 "move  $6,%3	\n" /* a2=parent_tid */			\
		 "li    $7,0	\n"	    /* a3 = tls is 0 */		\
		 "move  $8,%4	\n"	    /* a4 = child_tid */	\
		 "li    $2, "__stringify(__NR_clone)"	\n"		\
		 "syscall  	\n"	/* syscall */			\
		 "sync  	\n"				\
		 "bnez	$7,err  	\n"				\
		 "nop  	\n"						\
		 "beqz	$2,thread_start  	\n"			\
		 "nop 	                        \n"			\
		 "move %0,$2 	                \n"			\
		 "b  end 	                \n"			\
		 "err:break  \n"					\
		 "thread_start:  	\n"				\
		 "ld 	$25,0($29)         \n"				\
		 "ld 	$4,8($29)      \n"				\
		 "jal 	$25  \n"					\
		 "nop  \n"						\
		 "end:  \n"						\
		     : "=r"(ret)					\
		     : "r"(clone_flags),				\
		       "m"(new_sp),					\
		       "r"(&parent_tid),				\
		       "r"(&thread_args[i].pid),			\
		       "r"(clone_restore_fn),				\
		       "r"(&thread_args[i])				\
		 :"$2","$4","$5","$6","$7","$8","$25","$29","memory")

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args, \
			      clone_restore_fn)	do { \
	pr_err("This architecture does not support clone3() with set_tid, yet!\n"); \
	ret = -1; \
} while (0)

#define kdat_compatible_cr()			0
#define arch_map_vdso(map, compat)		-1

static inline void *alloc_compat_syscall_stack(void) { return NULL; }
static inline void free_compat_syscall_stack(void *stack32) { }
int restore_gpregs(struct rt_sigframe *f, UserMipsRegsEntry *r);
int restore_nonsigframe_gpregs(UserMipsRegsEntry *r);

#define ARCH_HAS_SHMAT_HOOK
unsigned long arch_shmat(int shmid, void *shmaddr,
			int shmflg, unsigned long size);

#endif
