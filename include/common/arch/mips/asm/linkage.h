#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#define zero $0 /* wired zero */
#define AT   $1 /* assembler temp  - uppercase because of ".set at" */
#define v0   $2
#define v1   $3

#define a0 $4
#define a1 $5
#define a2 $6
#define a3 $7
#define a4 $8
#define a5 $9
#define a6 $10
#define a7 $11
#define t0 $12
#define t1 $13
#define t2 $14
#define t3 $15

#define s0 $16 /* callee saved */
#define s1 $17
#define s2 $18
#define s3 $19
#define s4 $20
#define s5 $21
#define s6 $22
#define s7 $23
#define t8 $24 /* caller saved */
#define t9 $25
#define jp $25 /* PIC jump register */
#define k0 $26 /* kernel scratch */
#define k1 $27
#define gp $28 /* global pointer */
#define sp $29 /* stack pointer */
#define fp $30 /* frame pointer */
#define s8 $30 /* same like fp! */
#define ra $31 /* return address */

#define __ALIGN	    .align 8
#define __ALIGN_STR ".align 8"

#define GLOBAL(name) \
	.globl name; \
	name:

#define ENTRY(name)            \
	.globl name;           \
	__ALIGN;               \
	.type name, @function; \
	name:

#define END(sym) .size sym, .- sym

#endif /* __CR_LINKAGE_H__ */
