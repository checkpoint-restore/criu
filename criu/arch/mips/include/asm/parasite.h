#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline void arch_get_tls(tls_t *ptls)
{
/*fixme: gysun*/
      //     	user_regs_struct_t test_regs1;
//	int ret = ptrace(PTRACE_GET_THREAD_AREA,pid,NULL,ptls);
//	*ptls = ((tls_t (*)(void))0xffff0fe0)();
    
	asm volatile(							
		     "move $4, %0				    \n"	
		     "li $2,  "__stringify(__NR_get_thread_area)"  \n" 
		     "syscall					    \n"	
		     :							
		     : "r"(ptls)					
		     : "$4","$2","memory");

}

#endif
