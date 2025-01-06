#ifndef __CR_PROCESSOR_FLAGS_H__
#define __CR_PROCESSOR_FLAGS_H__

/* Copied from the Linux kernel header arch/arm/include/uapi/asm/ptrace.h */

/*
 * PSR bits
 */
#define USR26_MODE  0x00000000
#define FIQ26_MODE  0x00000001
#define IRQ26_MODE  0x00000002
#define SVC26_MODE  0x00000003
#define USR_MODE    0x00000010
#define FIQ_MODE    0x00000011
#define IRQ_MODE    0x00000012
#define SVC_MODE    0x00000013
#define ABT_MODE    0x00000017
#define UND_MODE    0x0000001b
#define SYSTEM_MODE 0x0000001f
#define MODE32_BIT  0x00000010
#define MODE_MASK   0x0000001f
#define PSR_T_BIT   0x00000020
#define PSR_F_BIT   0x00000040
#define PSR_I_BIT   0x00000080
#define PSR_A_BIT   0x00000100
#define PSR_E_BIT   0x00000200
#define PSR_J_BIT   0x01000000
#define PSR_Q_BIT   0x08000000
#define PSR_V_BIT   0x10000000
#define PSR_C_BIT   0x20000000
#define PSR_Z_BIT   0x40000000
#define PSR_N_BIT   0x80000000

/*
 * Groups of PSR bits
 */
#define PSR_f 0xff000000 /* Flags	*/
#define PSR_s 0x00ff0000 /* Status	*/
#define PSR_x 0x0000ff00 /* Extension	*/
#define PSR_c 0x000000ff /* Control	*/

#endif
