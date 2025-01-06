#ifndef __CR_ASM_H__
#define __CR_ASM_H__

#ifdef __GCC_ASM_FLAG_OUTPUTS__
#define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
#define CC_OUT(c) "=@cc" #c
#else
#define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
#define CC_OUT(c) [_cc_##c] "=qm"
#endif

#ifdef __ASSEMBLY__
#define __ASM_FORM(x) x
#else
#define __ASM_FORM(x) " " #x " "
#endif

#ifndef __x86_64__
/* 32 bit */
#define __ASM_SEL(a, b) __ASM_FORM(a)
#else
/* 64 bit */
#define __ASM_SEL(a, b) __ASM_FORM(b)
#endif

#define __ASM_SIZE(inst, ...) __ASM_SEL(inst##l##__VA_ARGS__, inst##q##__VA_ARGS__)

#endif /* __CR_ASM_H__ */
