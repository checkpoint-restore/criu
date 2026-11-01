#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check that multi-page Copy-On-Write memory is intact and breaks properly after C/R";
const char *test_author = "Muskan Kumari <er.muskan09@gmail.com>";

#define NUM_PAGES    16
#define INITIAL_BYTE 0x5A
#define CHILD_BYTE   0x3C

int main(int argc, char **argv)
{
	task_waiter_t lock;
	size_t page_size;
	size_t buf_size;
	char *buf;
	pid_t pid;
	int status;

	test_init(argc, argv);
	task_waiter_init(&lock);

	page_size = PAGE_SIZE;
	buf_size = NUM_PAGES * page_size;

	buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		pr_perror("mmap failed");
		return 1;
	}

	memset(buf, INITIAL_BYTE, buf_size);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("test_fork failed");
		return 1;
	}

	if (pid == 0) {
		/* Child process */

		/* Verify memory before dump */
		for (size_t i = 0; i < buf_size; i++) {
			if ((unsigned char)buf[i] != INITIAL_BYTE) {
				pr_err("Child: Memory corrupted before dump at %zu\n", i);
				return 1;
			}
		}

		/* Signal parent that child is ready for dump */
		task_waiter_complete(&lock, 1);

		/* Wait for restore signal from parent */
		task_waiter_wait4(&lock, 2);

		/* Verify memory after restore */
		for (size_t i = 0; i < buf_size; i++) {
			if ((unsigned char)buf[i] != INITIAL_BYTE) {
				pr_err("Child: Memory corrupted after restore at %zu\n", i);
				return 1;
			}
		}

		/* Modify first page to break Copy-on-Write */
		memset(buf, CHILD_BYTE, page_size);

		for (size_t i = 0; i < page_size; i++) {
			if ((unsigned char)buf[i] != CHILD_BYTE) {
				pr_err("Child: COW modification failed at %zu\n", i);
				return 1;
			}
		}

		return 0;
	}

	/* Parent process */

	/* Wait until child is ready */
	task_waiter_wait4(&lock, 1);

	test_daemon();
	test_waitsig();

	/* Resume child after restore */
	task_waiter_complete(&lock, 2);

	/* Wait for child completion */
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Can't wait for child");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("Child exited abnormally or with failure (status %d)", status);
		return 1;
	}

	/* Verify parent buffer was NOT corrupted by child's COW write */
	for (size_t i = 0; i < buf_size; i++) {
		if ((unsigned char)buf[i] != INITIAL_BYTE) {
			fail("Parent: Memory affected by child COW write at %zu", i);
			return 1;
		}
	}

	pass();
	return 0;
}
