#ifndef __NR_mmap2
# define __NR_mmap2 192
#endif

#ifndef __ARM_NR_BASE
# define __ARM_NR_BASE                   0x0f0000
#endif

#ifndef __ARM_NR_breakpoint
# define __ARM_NR_breakpoint             (__ARM_NR_BASE+1)
#endif

#ifndef __ARM_NR_cacheflush
# define __ARM_NR_cacheflush             (__ARM_NR_BASE+2)
#endif

#ifndef __ARM_NR_usr26
# define __ARM_NR_usr26                  (__ARM_NR_BASE+3)
#endif

#ifndef __ARM_NR_usr32
# define __ARM_NR_usr32                  (__ARM_NR_BASE+4)
#endif

#ifndef __ARM_NR_set_tls
# define __ARM_NR_set_tls                (__ARM_NR_BASE+5)
#endif
