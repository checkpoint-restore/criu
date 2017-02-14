#ifndef __CR_ASM_FPU_H__
#define __CR_ASM_FPU_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <compel/common/compiler.h>

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

struct xsave_struct_ia32 {
	struct i387_fxsave_struct	i387;
	struct xsave_hdr_struct		xsave_hdr;
	struct ymmh_struct		ymmh;
} __packed;

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
} fpu_state_64_t;

struct user_i387_ia32_struct {
	uint32_t			cwd;		/* FPU Control Word		*/
	uint32_t			swd;		/* FPU Status Word		*/
	uint32_t			twd;		/* FPU Tag Word			*/
	uint32_t			fip;		/* FPU IP Offset		*/
	uint32_t			fcs;		/* FPU IP Selector		*/
	uint32_t			foo;		/* FPU Operand Pointer Offset	*/
	uint32_t			fos;		/* FPU Operand Pointer Selector	*/
	uint32_t			st_space[20];   /* 8*10 bytes for each FP-reg = 80 bytes */
} __packed;

typedef struct {
	struct {
		struct user_i387_ia32_struct	i387_ia32;

		/* Software status information [not touched by FSAVE]:		*/
		uint32_t			status;
	} __packed fregs_state;
	union {
		struct xsave_struct_ia32	xsave;
		uint8_t				__pad[sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE];
	} __packed;
}  __packed fpu_state_ia32_t;

/*
 * This one is used in restorer.
 */
typedef struct {
	union {
		fpu_state_64_t			fpu_state_64;
		fpu_state_ia32_t		fpu_state_ia32;
	};

	uint8_t has_fpu;
} fpu_state_t;

extern void compel_convert_from_fxsr(struct user_i387_ia32_struct *env,
				     struct i387_fxsave_struct *fxsave);

#endif /* __CR_ASM_FPU_H__ */
