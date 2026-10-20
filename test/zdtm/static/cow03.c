#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Restore a child whose private file VMA maps a different offset than parent";
const char *test_author = "Aman Vaibhav <amanvaibhav109@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	task_waiter_t waiter;
	char page[PAGE_SIZE];
	char *guard, *addr;
	pid_t pid;
	int fd, status;

	test_init(argc, argv);
	task_waiter_init(&waiter);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		pr_perror("Can't create %s", filename);
		return 1;
	}

	memset(page, 'A', sizeof(page));
	if (pwrite(fd, page, sizeof(page), 0) != sizeof(page)) {
		pr_perror("pwrite offset 0");
		close(fd);
		return 1;
	}

	memset(page, 'B', sizeof(page));
	if (pwrite(fd, page, sizeof(page), PAGE_SIZE) != sizeof(page)) {
		pr_perror("pwrite offset PAGE_SIZE");
		close(fd);
		return 1;
	}

	/*
	 * Reserve 3 pages with PROT_NONE and map the middle page.
	 * The guard pages prevent the kernel from merging this VMA with
	 * adjacent mappings, keeping start and end boundaries stable.
	 */
	guard = mmap(NULL, 3 * PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guard == MAP_FAILED) {
		pr_perror("mmap guard");
		close(fd);
		return 1;
	}

	addr = guard + PAGE_SIZE;

	/* Parent maps offset 0 (page 'A') */
	if (mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0) != addr) {
		pr_perror("Parent mmap offset 0");
		close(fd);
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		close(fd);
		return 1;
	}

	if (pid == 0) {
		/*
		 * Child remaps the exact same address to offset PAGE_SIZE (page 'B').
		 * Prior to the fix, check_cow_vmas() ignored pgoff and treated this
		 * as COW-inherited from parent, corrupting child's data with 'A'.
		 */
		if (mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
			 fd, PAGE_SIZE) != addr) {
			pr_perror("Child mmap offset PAGE_SIZE");
			close(fd);
			return 1;
		}

		close(fd);

		if (*addr != 'B') {
			fail("Child file offset is wrong before C/R");
			return 1;
		}

		/* Signal ready for checkpoint */
		task_waiter_complete(&waiter, 1);

		/* Wait for restore to finish */
		task_waiter_wait4(&waiter, 2);

		if (*addr != 'B') {
			fail("Child file offset corrupted after restore (expected 'B', got '%c')", *addr);
			return 1;
		}

		return 0;
	}

	close(fd);

	/* Wait until child has remapped its page */
	task_waiter_wait4(&waiter, 1);

	test_daemon();
	test_waitsig();

	/* Signal child that restore is complete */
	task_waiter_complete(&waiter, 2);

	if (*addr != 'A') {
		fail("Parent file offset corrupted after restore (expected 'A', got '%c')", *addr);
		return 1;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("Child exited abnormally (status %d)", status);
		return 1;
	}

	pass();
	return 0;
}
