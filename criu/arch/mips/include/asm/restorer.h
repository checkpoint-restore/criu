#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include <compel/asm/fpu.h>
#include "images/core.pb-c.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/sigframe.h>
#include "asm/compat.h"

#ifdef CONFIG_COMPAT
extern void restore_tls(tls_t *ptls);
extern int arch_compat_rt_sigaction(void *stack32, int sig,
		rt_sigaction_t_compat *act);
extern int set_compat_robust_list(uint32_t head_ptr, uint32_t len);
#else /* CONFIG_COMPAT */
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
#endif /* !CONFIG_COMPAT */

/*UNDO: gysun*/
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)      \
	asm volatile(							\
		     "move $5, %6				\n"	\
		     "move $6, %5				\n"	\
		     "move $7, %1				\n"	\
		     "move $8, %3				\n"	\
		     "move $9, %4				\n"	\
		     "break  					\n"	\
		     : "=r"(ret)					\
		     : "r"(clone_flags),				\
		       "m"(new_sp),					\
		       "r"(&parent_tid),				\
		       "r"(&thread_args[i].pid),			\
		       "r"(clone_restore_fn),				\
		       "r"(&thread_args[i])				\
		     :  "memory")

#define ARCH_FAIL_CORE_RESTORE					/* \ */
	/* asm volatile(						\ */
	/* 	     "movq %0, %%rsp			    \n"	\ */
	/* 	     "movq 0, %%rax			    \n"	\ */
	/* 	     "jmp *%%rax			    \n"	\ */
	/* 	     :						\ */
	/* 	     : "r"(ret)					\ */
	/* 	     : "memory") */

#ifndef ARCH_MAP_VDSO_32
# define ARCH_MAP_VDSO_32		0x2002
#endif

#ifndef ARCH_MAP_VDSO_64
# define ARCH_MAP_VDSO_64		0x2003
#endif

#define kdat_compatible_cr()			0
#define arch_map_vdso(map, compat)		-1


int restore_gpregs(struct rt_sigframe *f, UserMipsRegsEntry *r);
int restore_nonsigframe_gpregs(UserMipsRegsEntry *r);

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);

//extern int arch_map_vdso(unsigned long map_at, bool compatible);

#endif
