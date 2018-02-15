#ifndef __CR_ASM_KERNDAT_H__
#define __CR_ASM_KERNDAT_H__

extern int kdat_compatible_cr(void);
extern int kdat_can_map_vdso(void);
extern int kdat_x86_has_ptrace_fpu_xsave_bug(void);

#endif /* __CR_ASM_KERNDAT_H__ */
