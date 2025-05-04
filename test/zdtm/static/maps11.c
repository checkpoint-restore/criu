#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "zdtmtst.h"

#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

const char *test_doc = "Test MAP_DROPPABLE/MADV_WIPEONFORK mappings with 2 processes";
const char *test_author = "Alexander Mikhalitsyn <aleksandr.mikhalitsyn@canonical.com>";

bool mem_is_zero(const uint8_t *buffer, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		if (buffer[i] != 0)
			return false;

	return true;
}

int main(int argc, char **argv)
{
	uint8_t *p1, *p2;
	pid_t pid;
	int status;
	const char data[] = "MADV_WIPEONFORK vma data";
	bool criu_was_there = false;
	struct stat st1, st2;

	test_init(argc, argv);

	p1 = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE,
		  MAP_DROPPABLE | MAP_ANONYMOUS, 0, 0);
	if (p1 == MAP_FAILED) {
		if (errno == EINVAL) {
			skip("mmap failed, no kernel support for MAP_DROPPABLE\n");
			goto skip;
		} else {
			pr_perror("mmap failed");
			return -1;
		}
	}

	p2 = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (p2 == MAP_FAILED) {
		pr_perror("mmap failed");
		return 1;
	}

	if (madvise(p2, sizeof(data), MADV_WIPEONFORK)) {
		pr_perror("madvise failed");
		return -1;
	}

	/* contents of this mapping is supposed to be dropped after C/R */
	memcpy(p1, data, sizeof(data));

	/* contents of this mapping is supposed to be dropped after fork() */
	memcpy(p2, data, sizeof(data));

	/*
	 * Let's spawn a process before C/R so our mappings get inherited
	 * then, after C/R we need to ensure that CRIU memory premapping
	 * machinery works properly.
	 *
	 * It is important, because we restore MADV_WIPEONFORK on a later
	 * stages (after vma premapping happens) and we need to ensure that
	 * CRIU handles everything in a right way.
	 */
	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return 1;
	}

	if (pid == 0) {
		test_waitsig();

		/*
		 * Both mappings have VM_WIPEONFORK flag set,
		 * so we expect to have it null-ified after fork().
		 */
		if (!mem_is_zero(p1, sizeof(data)) ||
		    !mem_is_zero(p2, sizeof(data))) {
			pr_err("1st child: memory check failed\n");
			return 1;
		}

		return 0;
	}

	/*
	 * A simple way to detect if C/R happened is to compare st_ino
	 * fields of stat() on the procfs files of the current task.
	 *
	 * Hopefully, this terrible hack is never used in real-world
	 * applications ;-) Here, we only need this to make test
	 * to pass with/without --nocr option.
	 */
	if (stat("/proc/self/status", &st1)) {
		pr_perror("stat");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* signal a child process to continue */
	if (kill(pid, SIGTERM)) {
		pr_perror("kill");
		goto err;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("1st waitpid");
		goto err;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("1st process didn't exit cleanly: status=%d", status);
		goto err;
	}

	if (stat("/proc/self/status", &st2)) {
		pr_perror("stat");
		return 1;
	}

	/* detect CRIU */
	criu_was_there = st1.st_ino != st2.st_ino;

	/*
	 * We should mark failure if one of the following happens:
	 * 1. MAP_DROPPABLE memory is not zero after C/R
	 * 2. MAP_DROPPABLE memory somehow changed without C/R
	 *    (kernel issue? memory pressure?)
	 * 3. MADV_WIPEONFORK memory is not preserved
	 *
	 * We care about 2nd case only because we would like test
	 * to pass even with --nocr zdtm.py option.
	 */
	if ((criu_was_there && !mem_is_zero(p1, sizeof(data))) ||
	    (!criu_was_there && memcmp(p1, data, sizeof(data))) ||
	    memcmp(p2, data, sizeof(data))) {
		fail("Data mismatch");
		return 1;
	}

	/* contents of these mappings is supposed to be dropped after fork() */
	memcpy(p1, data, sizeof(data));
	memcpy(p2, data, sizeof(data));

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return 1;
	}

	if (pid == 0) {
		if (!mem_is_zero(p1, sizeof(data)) ||
		    !mem_is_zero(p2, sizeof(data))) {
			pr_err("2nd child: memory check failed\n");
			return 1;
		}

		return 0;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("2nd waitpid");
		goto err;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("2nd process didn't exit cleanly: status=%d", status);
		goto err;
	}

	pass();

	return 0;
err:
	if (waitpid(-1, NULL, WNOHANG) == 0) {
		kill(pid, SIGTERM);
		wait(NULL);
	}
	return 1;

skip:
	test_daemon();
	test_waitsig();
	pass();
	return 0;
}
