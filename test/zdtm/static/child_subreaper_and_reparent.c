#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check that child subreaper does not affect reparenting";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

enum {
	TEST_FORK,
	TEST_SAVE,
	TEST_CRIU,
	TEST_CHECK,
	TEST_EXIT,
};

struct shared {
	futex_t fstate;
	int parent_before_cr;
	int parent_after_cr;
} *sh;

int orphan(void)
{
	/*
	 * Wait until reparented to the pidns init. (By waiting
	 * for the SUBREAPER to reap our parent.)
	 */
	futex_wait_until(&sh->fstate, TEST_SAVE);

	sh->parent_before_cr = getppid();

	/* Return the control back to MAIN worker to do C/R */
	futex_set_and_wake(&sh->fstate, TEST_CRIU);
	futex_wait_until(&sh->fstate, TEST_CHECK);

	sh->parent_after_cr = getppid();

	futex_set_and_wake(&sh->fstate, TEST_EXIT);
	return 0;
}

int helper(void)
{
	int pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork");
		return 1;
	} else if (pid == 0) {
		exit(orphan());
	}
	return 0;
}

int subreaper(void)
{
	int pid, ret, status;

	setsid();

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork");
		return 1;
	} else if (pid == 0) {
		exit(helper());
	}

	/* Reap the HELPER */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_perror("Wrong exit status for helper: %d", status);
		return 1;
	}

	ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	if (ret) {
		pr_perror("Can't set child subreaper attribute, err = %d", ret);
		return 1;
	}

	/* Give control to ORPHAN to save it's parent */
	futex_set_and_wake(&sh->fstate, TEST_SAVE);
	futex_wait_until(&sh->fstate, TEST_EXIT);
	return 0;
}

int main(int argc, char **argv)
{
	int pid, status;

	sh = mmap(NULL, sizeof(struct shared), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Failed to alloc shared region");
		exit(1);
	}

	futex_set(&sh->fstate, TEST_FORK);

	test_init(argc, argv);

	setsid();

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork");
		exit(1);
	} else if (pid == 0) {
		exit(subreaper());
	}

	/* Wait until ORPHAN is ready to C/R */
	futex_wait_until(&sh->fstate, TEST_CRIU);

	test_daemon();
	test_waitsig();

	/* Give control to ORPHAN to check it's parent */
	futex_set_and_wake(&sh->fstate, TEST_CHECK);
	futex_wait_until(&sh->fstate, TEST_EXIT);

	/* Cleanup */
	while (wait(&status) > 0) {
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("Wrong exit status: %d", status);
			return 1;
		}
	}

	if (sh->parent_before_cr != sh->parent_after_cr)
		fail("Parent mismatch before %d after %d", sh->parent_before_cr, sh->parent_after_cr);
	else
		pass();
	return 0;
}
