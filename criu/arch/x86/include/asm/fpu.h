#ifndef __CR_ASM_FPU_H__
#define __CR_ASM_FPU_H__

#include <sys/types.h>
#include <stdbool.h>

#include "common/compiler.h"
#include "asm/int.h"

#define FP_MIN_ALIGN_BYTES		64

#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

#define XSTATE_FP			0x1
#define XSTATE_SSE			0x2
#define XSTATE_YMM			0x4

#define FXSAVE_SIZE			512
#define XSAVE_SIZE			832

struct fpx_sw_bytes {
	u32				magic1;
	u32				extended_size;
	u64				xstate_bv;
	u32				xstate_size;
	u32				padding[7];
};

struct i387_fxsave_struct {
	u16				cwd; /* Control Word			*/
	u16				swd; /* Status Word			*/
	u16				twd; /* Tag Word			*/
	u16				fop; /* Last Instruction Opcode		*/
	union {
		struct {
			u64		rip; /* Instruction Pointer		*/
			u64		rdp; /* Data Pointer			*/
		};
		struct {
			u32		fip; /* FPU IP Offset			*/
			u32		fcs; /* FPU IP Selector			*/
			u32		foo; /* FPU Operand Offset		*/
			u32		fos; /* FPU Operand Selector		*/
		};
	};
	u32				mxcsr;		/* MXCSR Register State */
	u32				mxcsr_mask;	/* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes				*/
	u32				st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes				*/
	u32				xmm_space[64];

	u32				padding[12];

	union {
		u32			padding1[12];
		u32			sw_reserved[12];
	};

} __aligned(16);

struct xsave_hdr_struct {
	u64				xstate_bv;
	u64				reserved1[2];
	u64				reserved2[5];
} __packed;

struct ymmh_struct {
	u32				ymmh_space[64];
} __packed;

/*
 * cpu requires it to be 64 byte aligned
 */
struct xsave_struct {
	struct i387_fxsave_struct	i387;
	struct xsave_hdr_struct		xsave_hdr;
	struct ymmh_struct		ymmh;
} __aligned(FP_MIN_ALIGN_BYTES) __packed;

/*
 * This one is used in restorer.
 */
typedef struct {
	/*
	 * The FPU xsave area must be continious and FP_MIN_ALIGN_BYTES
	 * aligned, thus make sure the compiler won't insert any hole here.
	 */

	union {
		struct xsave_struct	xsave;
		u8		__pad[sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE];
	};

	u8 has_fpu;
} fpu_state_t;

#endif /* __CR_ASM_FPU_H__ */
