#ifndef __CR_ASM_GENERIC_VDSO_H__
#define __CR_ASM_GENERIC_VDSO_H__

#define VDSO_PROT               (PROT_READ | PROT_EXEC)
#define VVAR_PROT               (PROT_READ)

/* Just in case of LPAE system PFN is u64. */
#define VDSO_BAD_PFN		(-1ull)
#define VVAR_BAD_PFN		(-1ull)
#define VDSO_BAD_ADDR		(-1ul)
#define VVAR_BAD_ADDR		(-1ul)
#define VDSO_BAD_SIZE		(-1ul)
#define VVAR_BAD_SIZE		(-1ul)

#endif /* __CR_ASM_GENERIC_VDSO_H__ */
