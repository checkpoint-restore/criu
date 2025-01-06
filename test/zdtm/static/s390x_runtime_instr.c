#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <ucontext.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

#ifndef __NR_s390_runtime_instr
#define __NR_s390_runtime_instr 342
#endif
#define NT_S390_RI_CB 0x30d

#define BUF_SIZE (1024 * 1024)

const char *test_doc = "Check runtime-instrumentation";
/* Original test provided by Martin Schwidefsky <schwidefsky@de.ibm.com> */
const char *test_author = "Alice Frosi <alice@linux.vnet.ibm.com>";

struct runtime_instr_cb {
	unsigned long rca;
	unsigned long roa;
	unsigned long rla;

	unsigned int v : 1;
	unsigned int s : 1;
	unsigned int k : 1;
	unsigned int h : 1;
	unsigned int a : 1;
	unsigned int reserved1 : 3;
	unsigned int ps : 1;
	unsigned int qs : 1;
	unsigned int pc : 1;
	unsigned int qc : 1;
	unsigned int reserved2 : 1;
	unsigned int g : 1;
	unsigned int u : 1;
	unsigned int l : 1;
	unsigned int key : 4;
	unsigned int reserved3 : 8;
	unsigned int t : 1;
	unsigned int rgs : 3;

	unsigned int m : 4;
	unsigned int n : 1;
	unsigned int mae : 1;
	unsigned int reserved4 : 2;
	unsigned int c : 1;
	unsigned int r : 1;
	unsigned int b : 1;
	unsigned int j : 1;
	unsigned int e : 1;
	unsigned int x : 1;
	unsigned int reserved5 : 2;
	unsigned int bpxn : 1;
	unsigned int bpxt : 1;
	unsigned int bpti : 1;
	unsigned int bpni : 1;
	unsigned int reserved6 : 2;

	unsigned int d : 1;
	unsigned int f : 1;
	unsigned int ic : 4;
	unsigned int dc : 4;

	unsigned long reserved7;
	unsigned long sf;
	unsigned long rsic;
	unsigned long reserved8;
};

/*
 * Return PSW mask
 */
static inline unsigned long extract_psw(void)
{
	unsigned int reg1, reg2;

	asm volatile("epsw %0,%1" : "=d"(reg1), "=a"(reg2));
	return (((unsigned long)reg1) << 32) | ((unsigned long)reg2);
}

/*
 * Enable runtime-instrumentation
 */
static inline void rion(void)
{
	asm volatile(".word 0xaa01, 0x0000");
}

/*
 * Disable runtime-instrumentation
 */
static inline void rioff(void)
{
	asm volatile(".word 0xaa03, 0x0000");
}

/*
 * Modify the current runtime-instrumentation control block
 */
static inline void mric(struct runtime_instr_cb *cb)
{
	asm volatile(".insn rsy,0xeb0000000062,0,0,%0" : : "Q"(*cb));
}

/*
 * Store the current runtime-instrumentation control block
 */
static inline void stric(struct runtime_instr_cb *cb)
{
	asm volatile(".insn rsy,0xeb0000000061,0,0,%0" : "=Q"(*cb) : : "cc");
}

/*
 * Ensure that runtime-intstrumentation is still working after C/R
 */
int main(int argc, char **argv)
{
	struct runtime_instr_cb ricb, ricb_check;
	unsigned long *ricb_check_ptr = (unsigned long *)&ricb_check;
	unsigned long *ricb_ptr = (unsigned long *)&ricb;
	unsigned long psw_mask;
	void *buf;
	int i;

	test_init(argc, argv);
	buf = malloc(BUF_SIZE);
	memset(buf, 0, BUF_SIZE);
	memset(&ricb, 0, sizeof(ricb));
	/* Initialize the default RI control block in the kernel */
	if (syscall(__NR_s390_runtime_instr, 1, NULL) < 0) {
		if (errno == EOPNOTSUPP) {
			test_daemon();
			test_waitsig();
			skip("RI not supported");
			pass();
			free(buf);
			return 0;
		}
		fail("syscall(s390_runtime_instr) failed");
		free(buf);
		return -1;
	}
	/* Set buffer for RI */
	ricb.rca = ricb.roa = (unsigned long)buf;
	ricb.rla = (unsigned long)buf + BUF_SIZE;
	mric(&ricb);
	/* Enable RI - afterwards the PSW will have RI bit set */
	rion();
	psw_mask = extract_psw();
	/* Verify that the RI bit is set in the PSW */
	if (!(psw_mask & PSW_MASK_RI)) {
		fail("Failed to enable RI");
		return -1;
	}
	/* Collect RI records until we hit buffer-full condition */
	while (ricb.rca < ricb.rla + 1) {
		for (i = 0; i < 10000; i++)
			asm volatile("" : : : "memory");
		rioff();
		stric(&ricb);
		rion();
	}
	/* Disable RI */
	rioff();
	/* Save the current RI control block */
	stric(&ricb);
	ricb_check = ricb;
	/* Re-enable RI for checkpoint */
	rion();

	/* Do C/R now */
	test_daemon();
	test_waitsig();

	/* Verify that the RI bit is set in the PSW */
	psw_mask = extract_psw();
	if (!(psw_mask & PSW_MASK_RI)) {
		fail("RI bit in PSW not set");
		return -1;
	}
	/*
	 * Verify that the RI block has been restored correctly
	 * and the buffer is unchanged
	 */
	rioff();
	stric(&ricb);
	for (i = 0; i < 8; i++) {
		if (ricb_ptr[i] == ricb_check_ptr[i])
			continue;
		/* Skip sf field because its value may change */
		if (i == 6)
			continue;
		fail("%d:Got %016lx expected %016lx", i, ricb_ptr[i], ricb_check_ptr[i]);
		return -1;
	}

	pass();
	return 0;
}
