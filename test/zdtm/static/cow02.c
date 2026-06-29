#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Restore a COW child whose parent VMA is a PROT_NONE reservation";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

/*
 * A parent reserves an address range with PROT_NONE and never touches it.
 * Such a mapping has no "ac" flag in /proc/pid/smaps, so CRIU marks it
 * VMA_AREA_NOT_ACCOUNTABLE. After fork() the child turns the very same range
 * into a writable mapping and fills it with data.
 *
 * Ensure the child's mapping is restored separately, not through COW with the
 * parent's not-accountable PROT_NONE reservation, so CRIU has a writable
 * premap for the child's pages.
 */

#define MEM_SIZE (32 * 4096)

int main(int argc, char **argv)
{
	task_waiter_t lock;
	void *mem;
	pid_t pid;
	int status;
	uint32_t crc;

	test_init(argc, argv);
	task_waiter_init(&lock);

	/* Parent: reserve the range and never write to it. */
	mem = mmap(NULL, MEM_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't reserve memory");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return 1;
	}

	if (pid == 0) {
		/* Child: make the reservation writable and fill it. */
		crc = ~0;

		if (mprotect(mem, MEM_SIZE, PROT_READ | PROT_WRITE)) {
			pr_perror("Child can't mprotect");
			return 1;
		}
		datagen(mem, MEM_SIZE, &crc);

		/* Ready for C/R. */
		task_waiter_complete(&lock, 1);

		/* Wait until the parent has been restored. */
		task_waiter_wait4(&lock, 2);

		crc = ~0;
		if (datachk(mem, MEM_SIZE, &crc)) {
			fail("Child data corrupted after restore");
			return 1;
		}
		return 0;
	}

	/* Parent: wait for the child to populate its copy, stay PROT_NONE. */
	task_waiter_wait4(&lock, 1);

	test_daemon();
	test_waitsig();

	/* Restore succeeded -- let the child verify its content. */
	task_waiter_complete(&lock, 2);

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Can't wait for the child");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("Child exited abnormally (status %d)", status);
		return 1;
	}

	pass();
	return 0;
}
