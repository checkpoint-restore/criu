#ifndef __ASM_PARASITE_H__
#define __ASM_PARASITE_H__

static inline void arch_get_tls(tls_t *ptls)
{
    asm("rdhwr %0, $29" : "=r"(*ptls));

    	/* asm volatile(							 */
	/* 	     "move $4, %0				    \n"	 */
	/* 	     "li $2,  "__stringify(__NR_get_thread_area)"  \n"  */
	/* 	     "syscall					    \n"	 */
	/* 	     :							 */
	/* 	     : "r"(ptls)					 */
	/* 	     : "$4","$2","memory"); */

}

#endif
