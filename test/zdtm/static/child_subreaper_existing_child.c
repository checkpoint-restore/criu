#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check that property is restored for existing children";
const char *test_author	= "Michał Cłapiński <mclapinski@google.com>";

enum {
	TEST_FORK,
	TEST_CRIU,
	TEST_DIE,
	TEST_CHECK,
	TEST_EXIT,
};

struct shared {
	futex_t fstate;
	int ppid_after_reparent;
} *sh;


int orphan(void)
{
	/* Return the control back to MAIN worker to do C/R */
	futex_set_and_wake(&sh->fstate, TEST_CRIU);
	futex_wait_until(&sh->fstate, TEST_CHECK);

	sh->ppid_after_reparent = getppid();

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

	futex_wait_until(&sh->fstate, TEST_DIE);
	return 0;
}

int subreaper(void)
{
	int pid, ret, status;

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork");
		return 1;
	} else if (pid == 0) {
		exit(helper());
	}

	ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	if (ret) {
		pr_perror("Can't set child subreaper attribute, err = %d", ret);
		return 1;
	}

	/* Reap the HELPER */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_perror("Wrong exit status for HELPER: %d", status);
		return 1;
	}
	
	/* Give control to ORPHAN so it can check its parent */
	futex_set_and_wake(&sh->fstate, TEST_CHECK);
	futex_wait_until(&sh->fstate, TEST_EXIT);
	
	/* Cleanup: reap the ORPHAN */
	wait(&status);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_perror("Wrong exit status for ORPHAN: %d", status);
		return 1;
	}
	
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

	/* Give control to HELPER so it can die */
	futex_set_and_wake(&sh->fstate, TEST_DIE);
	futex_wait_until(&sh->fstate, TEST_EXIT);

	/* Cleanup: reap the SUBREAPER */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("Wrong exit status: %d", status);
		return 1;
	}

	if (sh->ppid_after_reparent != pid)
		fail("Orphan was reparented to %d instead of %d", sh->ppid_after_reparent, pid);
	else
		pass();
	return 0;
}
