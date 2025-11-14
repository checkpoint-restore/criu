#ifndef __UAPI_ASM_GCS_TYPES_H__
#define __UAPI_ASM_GCS_TYPES_H__

#ifndef NT_ARM_GCS
#define NT_ARM_GCS 0x410 /* ARM GCS state */
#endif

/* Shadow Stack/Guarded Control Stack interface */
#define PR_GET_SHADOW_STACK_STATUS	74
#define PR_SET_SHADOW_STACK_STATUS	75
#define PR_LOCK_SHADOW_STACK_STATUS	76

/* When set PR_SHADOW_STACK_ENABLE flag allocates a Guarded Control Stack */
#ifndef PR_SHADOW_STACK_ENABLE
#define PR_SHADOW_STACK_ENABLE		(1UL << 0)
#endif

/* Allows explicit GCS stores (eg. using GCSSTR) */
#ifndef PR_SHADOW_STACK_WRITE
#define PR_SHADOW_STACK_WRITE		(1UL << 1)
#endif

/* Allows explicit GCS pushes (eg. using GCSPUSHM) */
#ifndef PR_SHADOW_STACK_PUSH
#define PR_SHADOW_STACK_PUSH		(1UL << 2)
#endif

#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN 0x1     /* Set up a restore token in the shadow stack */
#endif

#define PR_SHADOW_STACK_ALL_MODES \
	PR_SHADOW_STACK_ENABLE | PR_SHADOW_STACK_WRITE | PR_SHADOW_STACK_PUSH

/* copied from: arch/arm64/include/asm/sysreg.h */
#define GCS_CAP_VALID_TOKEN 0x1
#define GCS_CAP_ADDR_MASK 0xFFFFFFFFFFFFF000ULL
#define GCS_CAP(x) ((((unsigned long)x) & GCS_CAP_ADDR_MASK) | GCS_CAP_VALID_TOKEN)
#define GCS_SIGNAL_CAP(addr) (((unsigned long)addr) & GCS_CAP_ADDR_MASK)

#include <asm/hwcap.h>

#ifndef HWCAP_GCS
#define HWCAP_GCS (1UL << 32)
#endif

#endif /* __UAPI_ASM_GCS_TYPES_H__ */