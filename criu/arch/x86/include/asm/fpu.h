#ifndef __CR_ASM_FPU_H__
#define __CR_ASM_FPU_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "common/compiler.h"

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
	uint32_t			magic1;
	uint32_t			extended_size;
	uint64_t			xstate_bv;
	uint32_t			xstate_size;
	uint32_t			padding[7];
};

struct i387_fxsave_struct {
	uint16_t			cwd; /* Control Word			*/
	uint16_t			swd; /* Status Word			*/
	uint16_t			twd; /* Tag Word			*/
	uint16_t			fop; /* Last Instruction Opcode		*/
	union {
		struct {
			uint64_t	rip; /* Instruction Pointer		*/
			uint64_t	rdp; /* Data Pointer			*/
		};
		struct {
			uint32_t	fip; /* FPU IP Offset			*/
			uint32_t	fcs; /* FPU IP Selector			*/
			uint32_t	foo; /* FPU Operand Offset		*/
			uint32_t	fos; /* FPU Operand Selector		*/
		};
	};
	uint32_t			mxcsr;		/* MXCSR Register State */
	uint32_t			mxcsr_mask;	/* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes				*/
	uint32_t			st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes				*/
	uint32_t			xmm_space[64];

	uint32_t			padding[12];

	union {
		uint32_t		padding1[12];
		uint32_t		sw_reserved[12];
	};

} __aligned(16);

struct xsave_hdr_struct {
	uint64_t			xstate_bv;
	uint64_t			reserved1[2];
	uint64_t			reserved2[5];
} __packed;

struct ymmh_struct {
	uint32_t			ymmh_space[64];
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
		uint8_t			__pad[sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE];
	};

	uint8_t has_fpu;
} fpu_state_t;

#endif /* __CR_ASM_FPU_H__ */
