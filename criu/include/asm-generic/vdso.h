#ifndef __CR_ASM_GENERIC_VDSO_H__
#define __CR_ASM_GENERIC_VDSO_H__

#define VDSO_PROT               (PROT_READ | PROT_EXEC)
#define VVAR_PROT               (PROT_READ)

#define VDSO_BAD_ADDR           (-1ul)
#define VVAR_BAD_ADDR           VDSO_BAD_ADDR
#define VDSO_BAD_PFN            (-1ull)
#define VVAR_BAD_PFN            VDSO_BAD_PFN

#endif /* __CR_ASM_GENERIC_VDSO_H__ */
