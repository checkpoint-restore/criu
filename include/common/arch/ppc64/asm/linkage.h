/*
 * Various PowerPc assembly definitions
 *
 * Copied from the kernel file arch/powerpc/include/asm/ppc_asm.h
 *
 * Copyright (C) 1995-1999 Gary Thomas, Paul Mackerras, Cort Dougan.
 */
#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#ifdef __ASSEMBLY__

#define GLOBAL(name)		\
	.globl name;		\
	name:

#define ENTRY(name)		\
	.globl name;		\
	.type name, @function;	\
	name:

#define END(sym)		\
	.size sym, . - sym


#define STACKFRAMESIZE 256
#define __STK_REG(i)   (112 + ((i)-14)*8)
#define STK_REG(i)     __STK_REG(__REG_##i)

/* The boring bits... */

/* Condition Register Bit Fields */

#define	cr0	0
#define	cr1	1
#define	cr2	2
#define	cr3	3
#define	cr4	4
#define	cr5	5
#define	cr6	6
#define	cr7	7


/*
 * General Purpose Registers (GPRs)
 *
 * The lower case r0-r31 should be used in preference to the upper
 * case R0-R31 as they provide more error checking in the assembler.
 * Use R0-31 only when really nessesary.
 */

#define	r0	%r0
#define	r1	%r1
#define	r2	%r2
#define	r3	%r3
#define	r4	%r4
#define	r5	%r5
#define	r6	%r6
#define	r7	%r7
#define	r8	%r8
#define	r9	%r9
#define	r10	%r10
#define	r11	%r11
#define	r12	%r12
#define	r13	%r13
#define	r14	%r14
#define	r15	%r15
#define	r16	%r16
#define	r17	%r17
#define	r18	%r18
#define	r19	%r19
#define	r20	%r20
#define	r21	%r21
#define	r22	%r22
#define	r23	%r23
#define	r24	%r24
#define	r25	%r25
#define	r26	%r26
#define	r27	%r27
#define	r28	%r28
#define	r29	%r29
#define	r30	%r30
#define	r31	%r31


/* Floating Point Registers (FPRs) */

#define	fr0	0
#define	fr1	1
#define	fr2	2
#define	fr3	3
#define	fr4	4
#define	fr5	5
#define	fr6	6
#define	fr7	7
#define	fr8	8
#define	fr9	9
#define	fr10	10
#define	fr11	11
#define	fr12	12
#define	fr13	13
#define	fr14	14
#define	fr15	15
#define	fr16	16
#define	fr17	17
#define	fr18	18
#define	fr19	19
#define	fr20	20
#define	fr21	21
#define	fr22	22
#define	fr23	23
#define	fr24	24
#define	fr25	25
#define	fr26	26
#define	fr27	27
#define	fr28	28
#define	fr29	29
#define	fr30	30
#define	fr31	31

/* AltiVec Registers (VPRs) */

#define	vr0	0
#define	vr1	1
#define	vr2	2
#define	vr3	3
#define	vr4	4
#define	vr5	5
#define	vr6	6
#define	vr7	7
#define	vr8	8
#define	vr9	9
#define	vr10	10
#define	vr11	11
#define	vr12	12
#define	vr13	13
#define	vr14	14
#define	vr15	15
#define	vr16	16
#define	vr17	17
#define	vr18	18
#define	vr19	19
#define	vr20	20
#define	vr21	21
#define	vr22	22
#define	vr23	23
#define	vr24	24
#define	vr25	25
#define	vr26	26
#define	vr27	27
#define	vr28	28
#define	vr29	29
#define	vr30	30
#define	vr31	31

/* VSX Registers (VSRs) */

#define	vsr0	0
#define	vsr1	1
#define	vsr2	2
#define	vsr3	3
#define	vsr4	4
#define	vsr5	5
#define	vsr6	6
#define	vsr7	7
#define	vsr8	8
#define	vsr9	9
#define	vsr10	10
#define	vsr11	11
#define	vsr12	12
#define	vsr13	13
#define	vsr14	14
#define	vsr15	15
#define	vsr16	16
#define	vsr17	17
#define	vsr18	18
#define	vsr19	19
#define	vsr20	20
#define	vsr21	21
#define	vsr22	22
#define	vsr23	23
#define	vsr24	24
#define	vsr25	25
#define	vsr26	26
#define	vsr27	27
#define	vsr28	28
#define	vsr29	29
#define	vsr30	30
#define	vsr31	31
#define	vsr32	32
#define	vsr33	33
#define	vsr34	34
#define	vsr35	35
#define	vsr36	36
#define	vsr37	37
#define	vsr38	38
#define	vsr39	39
#define	vsr40	40
#define	vsr41	41
#define	vsr42	42
#define	vsr43	43
#define	vsr44	44
#define	vsr45	45
#define	vsr46	46
#define	vsr47	47
#define	vsr48	48
#define	vsr49	49
#define	vsr50	50
#define	vsr51	51
#define	vsr52	52
#define	vsr53	53
#define	vsr54	54
#define	vsr55	55
#define	vsr56	56
#define	vsr57	57
#define	vsr58	58
#define	vsr59	59
#define	vsr60	60
#define	vsr61	61
#define	vsr62	62
#define	vsr63	63

/* SPE Registers (EVPRs) */

#define	evr0	0
#define	evr1	1
#define	evr2	2
#define	evr3	3
#define	evr4	4
#define	evr5	5
#define	evr6	6
#define	evr7	7
#define	evr8	8
#define	evr9	9
#define	evr10	10
#define	evr11	11
#define	evr12	12
#define	evr13	13
#define	evr14	14
#define	evr15	15
#define	evr16	16
#define	evr17	17
#define	evr18	18
#define	evr19	19
#define	evr20	20
#define	evr21	21
#define	evr22	22
#define	evr23	23
#define	evr24	24
#define	evr25	25
#define	evr26	26
#define	evr27	27
#define	evr28	28
#define	evr29	29
#define	evr30	30
#define	evr31	31

/* some stab codes */
#define N_FUN	36
#define N_RSYM	64
#define N_SLINE	68
#define N_SO	100

#define __REG_R0        0
#define __REG_R1        1
#define __REG_R2        2
#define __REG_R3        3
#define __REG_R4        4
#define __REG_R5        5
#define __REG_R6        6
#define __REG_R7        7
#define __REG_R8        8
#define __REG_R9        9
#define __REG_R10       10
#define __REG_R11       11
#define __REG_R12       12
#define __REG_R13       13
#define __REG_R14       14
#define __REG_R15       15
#define __REG_R16       16
#define __REG_R17       17
#define __REG_R18       18
#define __REG_R19       19
#define __REG_R20       20
#define __REG_R21       21
#define __REG_R22       22
#define __REG_R23       23
#define __REG_R24       24
#define __REG_R25       25
#define __REG_R26       26
#define __REG_R27       27
#define __REG_R28       28
#define __REG_R29       29
#define __REG_R30       30
#define __REG_R31       31



#endif  /* __ASSEMBLY__ */

#endif /* __CR_LINKAGE_H__ */
