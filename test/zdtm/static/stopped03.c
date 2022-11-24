#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check, that stopped by SIGTSTP tasks are restored correctly";
const char *test_author = "Yuriy Vasiliev <yuriy.vasiliev@openvz.org>";

#define STOP_SIGNO SIGTSTP
const char *stop_sigstr = "SIGTSTP";
enum {
	FUTEX_INITIALIZED = 0,
	TEST_CRIU,
	TEST_CHECK,
	TEST_DONE,
	TEST_EXIT,
	TEST_EMERGENCY_ABORT,
};

struct shared {
	futex_t fstate;
	int status;
	int code;
} *sh;

static int new_pgrp(void)
{
	siginfo_t infop;
	int ret = 1;
	pid_t pid;

	/*
	 * Set the PGID to avoid creating an orphaned process group,
	 * which is not to be affected by terminal-generated stop signals.
	 */
	setpgid(0, 0);

	pid = test_fork();
	if (pid < 0)
		goto err_cr;

	if (pid == 0) {
		/* wait for TEST_EXIT or TEST_EMERGENCY_ABORT*/
		futex_wait_while_lt(&sh->fstate, TEST_EXIT);
		exit(0);
	}

	if (kill(pid, STOP_SIGNO)) {
		pr_perror("Unable to send %s", stop_sigstr);
		goto err_cr;
	}

	if (waitid(P_PID, pid, &infop, WNOWAIT | WSTOPPED) < 0) {
		pr_perror("Unable to waitid %d", pid);
		goto err_cont;
	}

	sh->code = infop.si_code;
	sh->status = infop.si_status;

	/* Return the control back to MAIN worker to do C/R */
	futex_set_and_wake(&sh->fstate, TEST_CRIU);
	futex_wait_while_lt(&sh->fstate, TEST_CHECK);

	infop.si_code = 0;
	infop.si_status = 0;

	if (waitid(P_PID, pid, &infop, WNOWAIT | WSTOPPED) < 0) {
		pr_perror("Unable to waitid %d", pid);
		goto err_cont;
	}

	sh->code = infop.si_code;
	sh->status = infop.si_status;

	futex_set_and_wake(&sh->fstate, TEST_DONE);
	futex_wait_while_lt(&sh->fstate, TEST_EXIT);

	ret = 0;
err_cont:
	kill(pid, SIGCONT);
err_cr:
	if (ret)
		futex_set_and_wake(&sh->fstate, TEST_EMERGENCY_ABORT);
	if (pid > 0)
		wait(NULL);

	return ret;
}

int main(int argc, char **argv)
{
	int fail = 0;
	pid_t pid;

	test_init(argc, argv);

	sh = mmap(NULL, sizeof(struct shared), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Failed to alloc shared region");
		return 1;
	}

	futex_set(&sh->fstate, FUTEX_INITIALIZED);

	pid = test_fork();
	if (pid < 0) {
		fail = 1;
		goto out;
	}

	if (pid == 0)
		exit(new_pgrp());

	/* Wait until pgrp is ready to C/R */
	futex_wait_while_lt(&sh->fstate, TEST_CRIU);
	if (futex_get(&sh->fstate) == TEST_EMERGENCY_ABORT) {
		pr_err("Fail in child worker before C/R\n");
		fail = 1;
		goto out;
	}

	if (sh->code != CLD_STOPPED || sh->status != STOP_SIGNO) {
		pr_err("Process is not in correct state before C/R."
		       " Expected stop signo: %d. Get stop signo: %d\n",
		       STOP_SIGNO, sh->status);
		fail = 1;
		goto out;
	}

	test_daemon();
	test_waitsig();

	futex_set_and_wake(&sh->fstate, TEST_CHECK);
	futex_wait_while_lt(&sh->fstate, TEST_DONE);
	if (futex_get(&sh->fstate) == TEST_EMERGENCY_ABORT) {
		pr_err("Fail in child worker after C/R\n");
		goto out;
	}

	if (sh->code != CLD_STOPPED || sh->status != STOP_SIGNO) {
		fail = 1;
		pr_err("Process is not in correct state after C/R."
		       " Expected stop signo: %d. Get stop signo: %d\n",
		       STOP_SIGNO, sh->status);
	}

	if (!fail)
		pass();

	futex_set_and_wake(&sh->fstate, TEST_EXIT);
out:
	if (pid > 0)
		wait(NULL);

	munmap(sh, sizeof(struct shared));

	return fail;
}
