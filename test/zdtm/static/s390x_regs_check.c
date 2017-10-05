#include <linux/elf.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that FP and VX registers do not change";
const char *test_author = "Michael Holzheu <holzheu@linux.vnet.ibm.com>";

/*
 * This test case executes the following procedure:
 *
 * 1) Set registers to defined values
 * The main process creates one child process and within that process
 * NR_THREADS threads. Then the main process uses ptrace(SETREGS) to
 * set the registers in the child process and in all threads.
 *
 * 2) Detach from child and threads
 * Do this in order to allow criu to use ptrace for dumping.
 *
 * 3) Issue criu commands
 * Useful tests are: dump, dump --check-only, dump --leave-running
 *
 * 4) Check registers
 * Use ptrace(GETREGS) and compare with original values from step 1.
 *
 * This test can be used for two purposes:
 *
 * - Verify that "criu restore" sets the correct register sets
 *   from "criu dump":
 *   $ zdtmp.py run -t zdtm/static/s390x_regs_check
 *
 * - Verify that dumpee continues running with correct registers after
 *   parasite injection:
 *   $ zdtmp.py run --norst -t zdtm/static/s390x_regs_check
 *   $ zdtmp.py run --norst --pre 2 -t zdtm/static/s390x_regs_check
 *   $ zdtmp.py run --check-only -t zdtm/static/s390x_regs_check
 */
#define NR_THREADS 2
#define NR_THREADS_ALL (NR_THREADS + 1)

static pid_t thread_pids[NR_THREADS_ALL];
static int pipefd[2];

/*
 * Generic structure to define a register set and test data
 */
struct reg_set {
	const char *name;	/* Name of regset */
	int nr;			/* Number of regset */
	void *data;		/* Test data */
	int len;		/* Number of bytes of test data */
	bool optional;		/* Not all kernels/machines have this reg set */
	bool available;		/* Current kernel/machine has this reg set */
};

/*
 * s390 floating point registers
 */
struct prfpreg {
	uint32_t	fpc;
	uint64_t	fprs[16];
};

struct prfpreg prfpreg_data = {
	.fpc = 0,
	.fprs = {
		0x0000000000000000,
		0x1111111111111110,
		0x2222222222222220,
		0x3333333333333330,
		0x4444444444444440,
		0x5555555555555550,
		0x6666666666666660,
		0x7777777777777770,
		0x8888888888888880,
		0x9999999999999990,
		0xaaaaaaaaaaaaaaa0,
		0xbbbbbbbbbbbbbbb0,
		0xccccccccccccccc0,
		0xddddddddddddddd0,
		0xeeeeeeeeeeeeeee0,
		0xfffffffffffffff0,
	}
};

struct reg_set reg_set_prfpreg = {
	.name		= "PRFPREG",
	.nr		= NT_PRFPREG,
	.data		= &prfpreg_data,
	.len		= sizeof(prfpreg_data),
	.optional	= false,
};

/*
 * s390 vector VXRS_LOW registers
 */

#define NT_S390_VXRS_LOW	0x309

struct vxrs_low {
	uint64_t	regs[16];
};

struct vxrs_low vxrs_low_data = {
	.regs = {
		0x0000000000000001,
		0x1111111111111111,
		0x2222222222222221,
		0x3333333333333331,
		0x4444444444444441,
		0x5555555555555551,
		0x6666666666666661,
		0x7777777777777771,
		0x8888888888888881,
		0x9999999999999991,
		0xaaaaaaaaaaaaaaa1,
		0xbbbbbbbbbbbbbbb1,
		0xccccccccccccccc1,
		0xddddddddddddddd1,
		0xeeeeeeeeeeeeeee1,
		0xfffffffffffffff1,
	}
};

struct reg_set reg_set_vxrs_low = {
	.name		= "VXRS_LOW",
	.nr		= NT_S390_VXRS_LOW,
	.data		= &vxrs_low_data,
	.len		= sizeof(vxrs_low_data),
	.optional	= true,
};

/*
 * s390 vector VXRS_HIGH registers
 */

#define NT_S390_VXRS_HIGH	0x30a

struct vxrs_high {
	uint64_t	regs[32];
};

struct vxrs_high vxrs_high_data = {
	.regs = {
		0x0000000000000002, 0x0000000000000002,
		0x1111111111111112, 0x1111111111111112,
		0x2222222222222222, 0x2222222222222222,
		0x3333333333333332, 0x3333333333333332,
		0x4444444444444442, 0x4444444444444442,
		0x5555555555555552, 0x5555555555555552,
		0x6666666666666662, 0x6666666666666662,
		0x7777777777777772, 0x7777777777777772,
		0x8888888888888882, 0x8888888888888882,
		0x9999999999999992, 0x9999999999999992,
		0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
		0xbbbbbbbbbbbbbbb2, 0xbbbbbbbbbbbbbbb2,
		0xccccccccccccccc2, 0xccccccccccccccc2,
		0xddddddddddddddd2, 0xddddddddddddddd2,
		0xeeeeeeeeeeeeeee2, 0xeeeeeeeeeeeeeee2,
		0xfffffffffffffff2, 0xfffffffffffffff2,
	}
};

struct reg_set reg_set_vxrs_high = {
	.name		= "VXRS_HIGH",
	.nr		= NT_S390_VXRS_HIGH,
	.data		= &vxrs_high_data,
	.len		= sizeof(vxrs_high_data),
	.optional	= true,
};

/*
 * s390 guarded-storage registers
 */
#define NT_S390_GS_CB		0x30b
#define NT_S390_GS_BC		0x30c

struct gs_cb {
	uint64_t regs[4];
};

struct gs_cb gs_cb_data = {
	.regs = {
		0x0000000000000000,
		0x000000123400001a,
		0x5555555555555555,
		0x000000014b58a010,
	}
};

struct reg_set reg_set_gs_cb = {
	.name		= "GS_CB",
	.nr		= NT_S390_GS_CB,
	.data		= &gs_cb_data,
	.len		= sizeof(gs_cb_data),
	.optional	= true,
};

struct gs_cb gs_bc_data = {
	.regs = {
		0x0000000000000000,
		0x000000123400001a,
		0xffffffffffffffff,
		0x0000000aaaaaaaaa,
	}
};

struct reg_set reg_set_gs_bc = {
	.name		= "GS_BC_CB",
	.nr		= NT_S390_GS_BC,
	.data		= &gs_bc_data,
	.len		= sizeof(gs_bc_data),
	.optional	= true,
};

/*
 * s390 runtime-instrumentation control block
 */
#define NT_S390_RI_CB		0x30d

struct ri_cb {
	uint64_t regs[8];
};

struct ri_cb ri_cb_data = {
	.regs = {
			0x000002aa13aae000,
			0x000002aa13aad000,
			0x000002aa13aadfff,
			0xe0a1000400000000,
			0x0000000000000000,
			0x0000000000004e20,
			0x0000000000003479,
			0x0000000000000000,
	}
};

struct reg_set reg_set_ri_cb = {
	.name		= "RI_CB",
	.nr		= NT_S390_RI_CB,
	.data		= &ri_cb_data,
	.len		= sizeof(ri_cb_data),
	.optional	= true,
};

/*
 * Vector with all regsets
 */
struct reg_set *reg_set_vec[] = {
	&reg_set_prfpreg,
	&reg_set_vxrs_low,
	&reg_set_vxrs_high,
	&reg_set_gs_cb,
	&reg_set_gs_bc,
	&reg_set_ri_cb,
	NULL,
};

/*
 * Print hexdump for buffer with variable group parameter
 */
void util_hexdump_grp(const char *tag, const void *data, int grp,
		      int count, int indent)
{
	char str[1024], *ptr = str;
	const char *buf = data;
	int i, first = 1;

	for (i = 0; i < count; i++) {
		if (first) {
			ptr = str;
			ptr += sprintf(ptr, "%*s", indent, " ");
			if (tag)
				ptr += sprintf(ptr, "%s: ", tag);
			ptr += sprintf(ptr, "%08x: ", i);
			first = 0;
		}
		ptr += sprintf(ptr, "%02x", buf[i]);
		if (i % 16 == 15 || i + 1 == count) {
			test_msg("%s\n", str);
			first = 1;
		} else if (i % grp == grp - 1) {
			ptr += sprintf(ptr, " ");
		}
	}
}

/*
 * Print hexdump for buffer with fix grp parameter
 */
void util_hexdump(const char *tag, const void *data, int count)
{
	util_hexdump_grp(tag, data, sizeof(long), count, 0);
}

/*
 * Set regset for pid
 */
static int set_regset(pid_t pid, struct reg_set *reg_set)
{
	struct iovec iov;

	iov.iov_base = reg_set->data;
	iov.iov_len = reg_set->len;

	if (ptrace(PTRACE_SETREGSET, pid, reg_set->nr, iov) == 0) {
		test_msg(" REGSET: %12s -> DONE\n", reg_set->name);
		reg_set->available = true;
		return 0;
	}
	if (reg_set->optional) {
		switch (errno) {
		case EOPNOTSUPP:
		case ENODEV:
			test_msg(" REGSET: %12s -> not supported by machine\n",
				 reg_set->name);
			return 0;
		case EINVAL:
			test_msg(" REGSET: %12s -> not supported by kernel\n",
				 reg_set->name);
			return 0;
		default:
			break;
		}
	}
	pr_perror("PTRACE_SETREGSET for %s failed for pid %d",
		  reg_set->name, pid);
	return -1;
}

/*
 * Apply all regsets
 */
static int set_regset_all(pid_t pid)
{
	int i;

	for (i = 0; reg_set_vec[i] != NULL; i++) {
		if (set_regset(pid, reg_set_vec[i]))
			return -1;
	}
	return 0;
}

/*
 * Check if regset for pid has changed
 */
static int check_regset(pid_t pid, struct reg_set *reg_set)
{
	struct iovec iov;
	char *data;

	if (!reg_set->available)
		return 0;
	data = calloc(reg_set->len, 1);
	if (!data)
		return -1;

	iov.iov_base = data;
	iov.iov_len = reg_set->len;

	if (ptrace(PTRACE_GETREGSET, pid, reg_set->nr, iov) != 0) {
		pr_perror("PTRACE_SETREGSET for %s failed for pid %d",
			  reg_set->name, pid);
		free(data);
		return -1;
	}
	if (memcmp(data, reg_set->data, reg_set->len) != 0) {
		test_msg("RegSet %s changed for pid=%d\n", reg_set->name, pid);
		test_msg("Original values:\n");
		util_hexdump(reg_set->name, reg_set->data, reg_set->len);
		test_msg("New values:\n");
		util_hexdump(reg_set->name, data, reg_set->len);
		free(data);
		return -1;
	}
	free(data);
	return 0;
}

/*
 * Check all regsets
 */
static int check_regset_all(pid_t pid)
{
	int i;

	for (i = 0; reg_set_vec[i] != NULL; i++) {
		if (check_regset(pid, reg_set_vec[i]))
			return -1;
	}
	return 0;
}

/*
 * Send error to father
 */
static void send_error(void)
{
	int val = 0;

	if (write(pipefd[1], &val, sizeof(val)) == -1)
		pr_perror("write failed");
}

/*
 * Write tid to pipe and then loop without changing registers
 */
static inline void send_tid_and_loop(int fd)
{
	int tid = syscall(__NR_gettid);

	asm volatile(
		     "lgr	2,%0\n"	/* Arg 1: fd */
		     "la	3,%1\n" /* Arg 2: &tid */
		     "lghi	4,4\n"  /* Arg 3: sizeof(int) */
		     "svc	4\n"	/* __NR_write SVC: */
		     /* After SVC no more registers are changed */
		     "0:	j 0b\n" /* Loop here */
		     : : "d" (fd), "Q" (tid) : "2", "3", "4");
}

/*
 * Function for threads
 */
static void *thread_func(void *fd)
{
	send_tid_and_loop(pipefd[1]);
	return NULL;
}

/*
 * Function executed by the child
 */
static void child_func(void)
{
	pthread_t thread;
	int i;

	/* Close read end of pipe */
	close(pipefd[0]);
	/* Create threads and send TID */
	for (i = 0; i < NR_THREADS; i++) {
		if (pthread_create(&thread, NULL, thread_func, NULL) != 0) {
			pr_perror("Error create thread: %d", i);
			send_error();
		}
	}
	/* Send tid and wait until get killed */
	send_tid_and_loop(pipefd[1]);
}

/*
 * Attach to a thread
 */
static int ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
		if (waitpid(pid, NULL, __WALL) < 0) {
			pr_perror("Waiting for thread %d failed", pid);
			return -1;
		}
		return 0;
	}
	pr_perror("Attach to thread %d failed", pid);
	return -1;
}

/*
 * Detach from a thread
 */
static int ptrace_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, 0, 0) == 0)
		return 0;
	pr_perror("Detach from thread %d failed", pid);
	return -1;
}

/*
 * Create child with threads and verify that registers are not corrupted
 */
int main(int argc, char *argv[])
{
	bool failed = false;
	pid_t child, pid;
	int i;

	test_init(argc, argv);

	test_msg("------------- START 1 PROCESS + %d THREADS ---------------\n",
	       NR_THREADS);
	if (pipe(pipefd) == -1) {
		perror("pipe failed");
		exit(EXIT_FAILURE);
	}
	child = fork();

	if (child == 0)
		child_func();

	/* Parent */
	for (i = 0; i < NR_THREADS_ALL; i++) {
		if (read(pipefd[0], &pid, sizeof(pid_t)) == -1) {
			perror("Read from pipe failed");
			failed = true;
			goto kill_all_threads;
		}
		if (pid == 0) {
			pr_err("Not all threads are started\n");
			failed = true;
			goto kill_all_threads;
		}
		test_msg("STARTED: pid = %d\n", pid);
		thread_pids[i] = pid;
	}

	/* Close write end */
	close(pipefd[1]);
	test_msg("---------------------- SET REGISTERS --------------------\n");
	for (i = 0; i < NR_THREADS_ALL; i++) {
		pid = thread_pids[i];
		test_msg("SET: pid = %d\n", pid);
		ptrace_attach(pid);
		set_regset_all(pid);
		ptrace_detach(pid);
	}

	test_daemon();
	test_waitsig();

	test_msg("-------------------- CHECK REGISTERS --------------------\n");
	for (i = 0; i < NR_THREADS_ALL; i++) {
		pid = thread_pids[i];
		test_msg("CHECK: pid = %d:\n", pid);
		ptrace_attach(pid);
		if (check_regset_all(pid) == 0) {
			test_msg(" -> OK\n");
		} else {
			test_msg(" -> FAIL\n");
			failed = true;
		}
		ptrace_detach(pid);
	}
	test_msg("----------------------- CLEANUP  ------------------------\n");

kill_all_threads:
	for (i = 0; i < NR_THREADS_ALL; i++) {
		pid = thread_pids[i];
		if (pid == 0)
			continue;
		test_msg("KILL: pid = %d\n", pid);
		kill(pid, SIGTERM);
	}

	if (failed) {
		fail("Registers changed");
		return 1;
	}
	pass();
	return 0;
}
