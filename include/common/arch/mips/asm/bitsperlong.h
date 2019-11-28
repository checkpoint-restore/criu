#ifndef __CR_BITSPERLONG_H__
#define __CR_BITSPERLONG_H__

#ifdef CONFIG_MIPS
# define BITS_PER_LONG 64
#else
# define BITS_PER_LONG 32
#endif

#endif /* __CR_BITSPERLONG_H__ */
