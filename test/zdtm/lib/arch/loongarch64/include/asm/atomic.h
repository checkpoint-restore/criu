#ifndef __CR_ATOMIC_H__
#define __CR_ATOMIC_H__

typedef uint32_t atomic_t;

#define atomic_get(v)	 (*(volatile int *)v)
#define atomic_set(v, i) (*(v) = (i))

static inline int __atomic_add(int i, atomic_t *v)
{
	int result;
	asm volatile("amadd_db.w %1, %2, %0" : "+ZB"(*v), "=&r"(result) : "r"(i) : "memory");
	return result + i;
}

static inline void atomic_add(int i, atomic_t *v)
{
	__atomic_add(i, v);
}

static inline int atomic_add_return(int i, atomic_t *v)
{
	return __atomic_add(i, v);
}

#define atomic_sub(i, v)	atomic_add(-(int)i, v)
#define atomic_sub_return(i, v) atomic_add_return(-(int)i, v)
#define atomic_inc(v)		atomic_add_return(1, v)
#define atomic_dec(v)		atomic_sub_return(1, v)
#define atomic_dec_return(v)	atomic_sub_return(1, v)

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	int ret;
	asm volatile("1:                     \n"
		     " ll.w  %0, %1          \n"
		     " bne   %0, %2, 2f      \n"
		     " or    $t0, %3, $zero  \n"
		     " sc.w  $t0, %1         \n"
		     " beqz  $t0, 1b         \n"
		     "2:                     \n"
		     " dbar  0               \n"
		     : "=&r"(ret), "+ZB"(*ptr)
		     : "r"(old), "r"(new)
		     : "t0", "memory");
	return ret;
}

#endif /* __CR_ATOMIC_H__ */
