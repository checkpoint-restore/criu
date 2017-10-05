#include <linux/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lock.h"
#include "zdtmtst.h"

#define NR_THREADS	4
#define GS_ENABLE	0
#define GS_SET_BC_CB	2
#define GS_BROADCAST	4

#ifndef __NR_guarded_storage
#define __NR_guarded_storage   378
#endif

const char *test_doc = "Check the guarded storage broadcast";
/* Original test provided by Martin Schwidefsky <schwidefsky@de.ibm.com> */
const char *test_author = "Alice Frosi <alice@linux.vnet.ibm.com>";

static unsigned long main_thread_tid;

/*
 * This test case executes the following procedure:
 *
 * 1) The parent thread creates NR_THREADS child threads
 *
 * 2) For each thread (including the parent thread):
 *    - Enable guarded-storage
 *    - Set the guarded-storage broadcast control block and
 *      specify gs_handler as Guarded-Storage-Event Parameter-List
 *      address
 *
 * 3) Dump and restore
 *
 * 4) Guarded-storage broadcast event
 *    - Child threads: Wait until main thread does GS broadcast
 *    - Parent thread: Trigger GS broadcast
 *
 * 5) Verify that all GS works as expected and all threads have been
 *    executed the gs_handler
 */

struct gs_cb {
	__u64 reserved;
	__u64 gsd;
	__u64 gssm;
	__u64 gs_epl_a;
};

static futex_t futex;
static futex_t futex2;

/*
 * Load guarded-storage
 */
void load_guarded(unsigned long *mem);
asm(
	".global load_guarded\n"
	"load_guarded:\n"
	"	.insn rxy,0xe3000000004c,%r2,0(%r2)\n"
	"	br %r14\n"
	"	.size load_guarded,.-load_guarded\n");

/*
 * Inline assembly to deal with interrupted context to the call of
 * the GS handler. Load guarded can be turned into a branch to this
 * function.
 */
void gs_handler_asm(void);
asm(
	".globl gs_handler_asm\n"
	"gs_handler_asm:\n"
	"	lgr	%r14,%r15\n"
	"	aghi	%r15,-320\n"
	"	stmg	%r0,%r14,192(%r15)\n"
	"	stg	%r14,312(%r14)\n"
	"	la	%r2,160(%r15)\n"
	"	.insn	rxy,0xe30000000049,0,160(%r15)\n"
	"	lg	%r14,24(%r2)\n"
	"	lg	%r14,40(%r14)\n"
	"	la	%r14,6(%r14)\n"
	"	stg	%r14,304(%r15)\n"
	"	brasl	%r14,gs_handler\n"
	"	lmg	%r0,%r15,192(%r15)\n"
	"	br	%r14\n"
	"	.size gs_handler_asm,.-gs_handler_asm\n");

/*
 * GS handler called when GS event occurs
 */
void gs_handler(struct gs_cb *this_cb)
{
	unsigned long tid = syscall(SYS_gettid);
	test_msg("gs_handler for thread %016lx\n", tid);
	futex_dec_and_wake(&futex2);
}

/*
 * Entry point for threads
 */
static void *thread_run(void *param)
{
	unsigned long test = 0x1234000000;
	unsigned long *gs_epl;
	struct gs_cb *gs_cb;

	/* Enable guarded-storage */
	if (syscall(__NR_guarded_storage, GS_ENABLE) != 0) {
		fail("Unable to enable guarded storage");
		exit(1);
	}
	gs_epl = malloc(sizeof(unsigned long) * 6);
	gs_cb = malloc(sizeof(*gs_cb));
	if (gs_epl == NULL || gs_cb == NULL) {
		fail("Error allocating memory\n");
		exit(1);
	}
	gs_cb->gsd = 0x1234000000UL | 26;
	gs_cb->gssm = -1UL;
	gs_cb->gs_epl_a = (unsigned long) gs_epl;
	gs_epl[1] = (unsigned long) gs_handler_asm;
	/* Set the GS broadcast control block */
	syscall(__NR_guarded_storage, GS_SET_BC_CB, gs_cb);
	futex_dec_and_wake(&futex);
	/* Wait for all threads to set the GS broadcast control block */
	futex_wait_until(&futex, 0);
	test_msg("Thread %016lx staring loop\n",  syscall(SYS_gettid));
	/*
	 * Designate a guarded-storage section until the main task
	 * performs the GS_BROADCAST action and the following load_guarded
	 * will provoke the switch to the gs handler
	 */
	while (1)
		load_guarded(&test);
}

int main(int argc, char *argv[])
{
	pthread_t tids[NR_THREADS];
	int i;

	main_thread_tid = syscall(SYS_gettid);
	test_init(argc, argv);
	/* Enable guarded-storage */
	if (syscall(__NR_guarded_storage, GS_ENABLE) != 0) {
		if (errno == ENOSYS) {
			test_daemon();
			test_waitsig();
			skip("No guarded storage support");
			pass();
			return 0;
		}
		fail("Unable to enable guarded storage");
		return 1;
	}

	futex_set(&futex, NR_THREADS);

	for (i = 0; i < NR_THREADS; i++)
		pthread_create(tids + i, NULL, thread_run, NULL);

	test_msg("Waiting for thread startup\n");
	/* Wait for all threads to set the GS broadcast control block */
	futex_wait_until(&futex, 0);

	test_daemon();
	test_waitsig();

	test_msg("Doing broadcast\n");
	futex_set(&futex2, NR_THREADS);
	/*
	 * Triggers a GS event and force all the threads to execute
	 * the gs handler
	 */
	syscall(__NR_guarded_storage, GS_BROADCAST);

	test_msg("Waiting for thread completion\n");
	futex_wait_until(&futex2, 0);
	pass();
	return 0;
}
