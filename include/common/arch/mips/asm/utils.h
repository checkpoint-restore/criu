#ifndef __UTILS_H__
#define __UTILS_H__


/*new file :from kernel/mips
* fixme: gysun
*
*/

#define LOONGSON_LLSC_WAR               0
#define R10000_LLSC_WAR			0

#ifdef CONFIG_SMP
# define kernel_uses_llsc	1
#else
# define kernel_uses_llsc	0
#endif

typedef struct {
	int counter;
}atomic_t;

/*from kernel/linux-3.10.84/arch/mips/include/barrier.h*/
#if defined(CONFIG_WEAK_ORDERING) && defined(CONFIG_SMP)
# ifdef CONFIG_CPU_CAVIUM_OCTEON
#  define smp_mb()	__sync()
#  define smp_rmb()	barrier()
#  define smp_wmb()	__syncw()
# else
#  define smp_mb()	__asm__ __volatile__("sync" : : :"memory")
#  define smp_rmb()	__asm__ __volatile__("sync" : : :"memory")
#  define smp_wmb()	__asm__ __volatile__("sync" : : :"memory")
# endif
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#endif

#if defined(CONFIG_WEAK_REORDERING_BEYOND_LLSC) && defined(CONFIG_SMP)
#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2K)
#  define __WEAK_LLSC_MB	"	.set mips64r2\nsynci 0\n.set mips0\n"
# else
#define __WEAK_LLSC_MB		"	sync	\n"
# endif
#else
#define __WEAK_LLSC_MB		"		\n"
#endif

#define smp_llsc_mb()	__asm__ __volatile__(__WEAK_LLSC_MB : : :"memory")

#ifdef CONFIG_CPU_CAVIUM_OCTEON
#define smp_mb__before_llsc() smp_wmb()
#else
#define smp_mb__before_llsc() smp_llsc_mb()
#endif

#define smp_mb__before_atomic()	smp_mb__before_llsc()
#define smp_mb__after_atomic()	smp_llsc_mb()

#endif /* __UTILS_H__ */
