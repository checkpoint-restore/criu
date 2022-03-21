#ifndef __CR_ASM_FPU_H__
#define __CR_ASM_FPU_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <compel/common/compiler.h>

#define FP_MIN_ALIGN_BYTES 64
#define FXSAVE_ALIGN_BYTES 16

#define FP_XSTATE_MAGIC1 0x46505853U
#define FP_XSTATE_MAGIC2 0x46505845U
#ifndef FP_XSTATE_MAGIC2_SIZE
#define FP_XSTATE_MAGIC2_SIZE sizeof(FP_XSTATE_MAGIC2)
#endif

#define XSTATE_FP  0x1
#define XSTATE_SSE 0x2
#define XSTATE_YMM 0x4

#define FXSAVE_SIZE 512
/*
 * This used to be 4096 (one page). There is a comment below concerning
 * this size:
 *  "One page should be enough for the whole xsave state ;-)"
 * Which is kind of funny as it is no longer enough ;-)
 *
 * Older CPUs:
 * # cpuid -1 -l 0xd -s 0
 * ...
 *     bytes required by XSAVE/XRSTOR area     = 0x00000988 (2440)
 *
 * Newer CPUs (Sapphire Rapids):
 * # cpuid -1 -l 0xd -s 0
 * ...
 *     bytes required by XSAVE/XRSTOR area     = 0x00002b00 (11008)
 *
 * So one page is no longer enough... But:
 *
 * Four pages should be enough for the whole xsave state ;-)
 */

#define XSAVE_SIZE  4*4096

#define XSAVE_HDR_SIZE	 64
#define XSAVE_HDR_OFFSET FXSAVE_SIZE

#define XSAVE_YMM_SIZE	 256
#define XSAVE_YMM_OFFSET (XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

/*
 * List of XSAVE features Linux knows about:
 */
enum xfeature {
	XFEATURE_FP,
	XFEATURE_SSE,
	/*
	 * Values above here are "legacy states".
	 * Those below are "extended states".
	 */
	XFEATURE_YMM,
	XFEATURE_BNDREGS,
	XFEATURE_BNDCSR,
	XFEATURE_OPMASK,
	XFEATURE_ZMM_Hi256,
	XFEATURE_Hi16_ZMM,
	XFEATURE_PT,
	XFEATURE_PKRU,
	XFEATURE_HDC,

	XFEATURE_MAX,
};

#define XSTATE_CPUID 0x0000000d

#define XFEATURE_MASK_FP	(1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE	(1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM	(1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS	(1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR	(1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK	(1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256 (1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM	(1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT	(1 << XFEATURE_PT)
#define XFEATURE_MASK_PKRU	(1 << XFEATURE_PKRU)
#define XFEATURE_MASK_HDC	(1 << XFEATURE_HDC)
#define XFEATURE_MASK_MAX	(1 << XFEATURE_MAX)

#define XFEATURE_MASK_FPSSE  (XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512 (XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)

#define FIRST_EXTENDED_XFEATURE XFEATURE_YMM

/* Supervisor features */
#define XFEATURE_MASK_SUPERVISOR (XFEATURE_MASK_PT | XFEATURE_HDC)

/* All currently supported features */
#define XFEATURE_MASK_USER                                                                                           \
	(XFEATURE_MASK_FP | XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | \
	 XFEATURE_MASK_Hi16_ZMM | XFEATURE_MASK_PKRU | XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR)

/* xsave structure features which is safe to fill with garbage (see validate_random_xstate()) */
#define XFEATURE_MASK_FAULTINJ                                                                                       \
	(XFEATURE_MASK_FP | XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | \
	 XFEATURE_MASK_Hi16_ZMM)

struct fpx_sw_bytes {
	uint32_t magic1;
	uint32_t extended_size;
	uint64_t xstate_bv;
	uint32_t xstate_size;
	uint32_t padding[7];
};

struct i387_fxsave_struct {
	uint16_t cwd; /* Control Word			*/
	uint16_t swd; /* Status Word			*/
	uint16_t twd; /* Tag Word			*/
	uint16_t fop; /* Last Instruction Opcode		*/
	union {
		struct {
			uint64_t rip; /* Instruction Pointer		*/
			uint64_t rdp; /* Data Pointer			*/
		};
		struct {
			uint32_t fip; /* FPU IP Offset			*/
			uint32_t fcs; /* FPU IP Selector			*/
			uint32_t foo; /* FPU Operand Offset		*/
			uint32_t fos; /* FPU Operand Selector		*/
		};
	};
	uint32_t mxcsr;	     /* MXCSR Register State */
	uint32_t mxcsr_mask; /* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes				*/
	uint32_t st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes				*/
	uint32_t xmm_space[64];

	uint32_t padding[12];

	union {
		uint32_t padding1[12];
		uint32_t sw_reserved[12];
	};

} __aligned(FXSAVE_ALIGN_BYTES);

struct xsave_hdr_struct {
	uint64_t xstate_bv;
	uint64_t xcomp_bv;
	uint64_t reserved[6];
} __packed;

/*
 * xstate_header.xcomp_bv[63] indicates that the extended_state_area
 * is in compacted format.
 */
#define XCOMP_BV_COMPACTED_FORMAT ((uint64_t)1 << 63)

/*
 * State component 2:
 *
 * There are 16x 256-bit AVX registers named YMM0-YMM15.
 * The low 128 bits are aliased to the 16 SSE registers (XMM0-XMM15)
 * and are stored in 'struct fxregs_state::xmm_space[]' in the
 * "legacy" area.
 *
 * The high 128 bits are stored here.
 */
struct ymmh_struct {
	uint32_t ymmh_space[64];
} __packed;

/* Intel MPX support: */

struct mpx_bndreg {
	uint64_t lower_bound;
	uint64_t upper_bound;
} __packed;

/*
 * State component 3 is used for the 4 128-bit bounds registers
 */
struct mpx_bndreg_state {
	struct mpx_bndreg bndreg[4];
} __packed;

/*
 * State component 4 is used for the 64-bit user-mode MPX
 * configuration register BNDCFGU and the 64-bit MPX status
 * register BNDSTATUS.  We call the pair "BNDCSR".
 */
struct mpx_bndcsr {
	uint64_t bndcfgu;
	uint64_t bndstatus;
} __packed;

/*
 * The BNDCSR state is padded out to be 64-bytes in size.
 */
struct mpx_bndcsr_state {
	union {
		struct mpx_bndcsr bndcsr;
		uint8_t pad_to_64_bytes[64];
	};
} __packed;

/* AVX-512 Components: */

/*
 * State component 5 is used for the 8 64-bit opmask registers
 * k0-k7 (opmask state).
 */
struct avx_512_opmask_state {
	uint64_t opmask_reg[8];
} __packed;

/*
 * State component 6 is used for the upper 256 bits of the
 * registers ZMM0-ZMM15. These 16 256-bit values are denoted
 * ZMM0_H-ZMM15_H (ZMM_Hi256 state).
 */
struct avx_512_zmm_uppers_state {
	uint64_t zmm_upper[16 * 4];
} __packed;

/*
 * State component 7 is used for the 16 512-bit registers
 * ZMM16-ZMM31 (Hi16_ZMM state).
 */
struct avx_512_hi16_state {
	uint64_t hi16_zmm[16 * 8];
} __packed;

/*
 * State component 9: 32-bit PKRU register.  The state is
 * 8 bytes long but only 4 bytes is used currently.
 */
struct pkru_state {
	uint32_t pkru;
	uint32_t pad;
} __packed;

/*
 * State component 11 is Control-flow Enforcement user states
 */
struct cet_user_state {
	uint64_t cet;			/* user control-flow settings */
	uint64_t ssp;			/* user shadow stack pointer */
};

/*
 * This is our most modern FPU state format, as saved by the XSAVE
 * and restored by the XRSTOR instructions.
 *
 * It consists of a legacy fxregs portion, an xstate header and
 * subsequent areas as defined by the xstate header. Not all CPUs
 * support all the extensions, so the size of the extended area
 * can vary quite a bit between CPUs.
 *
 *
 * One page should be enough for the whole xsave state ;-)
 *
 * Of course it was not ;-) Now using four pages...
 *
 */
#define EXTENDED_STATE_AREA_SIZE (XSAVE_SIZE - sizeof(struct i387_fxsave_struct) - sizeof(struct xsave_hdr_struct) - sizeof(struct cet_user_state))

/*
 * cpu requires it to be 64 byte aligned
 */
struct xsave_struct {
	struct i387_fxsave_struct i387;
	struct xsave_hdr_struct xsave_hdr;
	union {
		/*
		 * This ymmh is unndeed, for
		 * backward compatibility.
		 */
		struct ymmh_struct ymmh;
		uint8_t extended_state_area[EXTENDED_STATE_AREA_SIZE];
	};
	struct cet_user_state cet;
} __aligned(FP_MIN_ALIGN_BYTES) __packed;

struct xsave_struct_ia32 {
	struct i387_fxsave_struct i387;
	struct xsave_hdr_struct xsave_hdr;
	union {
		/*
		 * This ymmh is unndeed, for
		 * backward compatibility.
		 */
		struct ymmh_struct ymmh;
		uint8_t extended_state_area[EXTENDED_STATE_AREA_SIZE];
	};
};

typedef struct {
	/*
	 * The FPU xsave area must be continuous and FP_MIN_ALIGN_BYTES
	 * aligned, thus make sure the compiler won't insert any hole here.
	 */

	union {
		struct xsave_struct xsave;
		uint8_t __pad[sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE];
	};

	uint8_t has_fpu;
} fpu_state_64_t;

struct user_i387_ia32_struct {
	uint32_t cwd;	       /* FPU Control Word		*/
	uint32_t swd;	       /* FPU Status Word		*/
	uint32_t twd;	       /* FPU Tag Word			*/
	uint32_t fip;	       /* FPU IP Offset		*/
	uint32_t fcs;	       /* FPU IP Selector		*/
	uint32_t foo;	       /* FPU Operand Pointer Offset	*/
	uint32_t fos;	       /* FPU Operand Pointer Selector	*/
	uint32_t st_space[20]; /* 8*10 bytes for each FP-reg = 80 bytes */
};

typedef struct {
	struct {
		struct user_i387_ia32_struct i387_ia32;

		/* Software status information [not touched by FSAVE]:		*/
		uint32_t status;
	} fregs_state;
	union {
		struct xsave_struct_ia32 xsave;
		uint8_t __pad[sizeof(struct xsave_struct) + FP_XSTATE_MAGIC2_SIZE];
	} __aligned(FXSAVE_ALIGN_BYTES);
} __aligned(FXSAVE_ALIGN_BYTES) fpu_state_ia32_t;

/*
 * This one is used in restorer.
 */
typedef struct {
	union {
		fpu_state_64_t fpu_state_64;
		struct {
			/* fpu_state_ia32->xsave has to be 64-byte aligned. */
			uint32_t __pad[2];
			fpu_state_ia32_t fpu_state_ia32;
		};
	};

	uint8_t has_fpu;
} fpu_state_t;

extern void compel_convert_from_fxsr(struct user_i387_ia32_struct *env, struct i387_fxsave_struct *fxsave);

#endif /* __CR_ASM_FPU_H__ */
