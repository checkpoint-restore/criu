#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check page content across fork (CoW)";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

/*
 * Allocate private anonymous memory, fill it with a known pattern, fork a
 * child, then have the child modify some pages (triggering CoW). After C/R,
 * verify that:
 *
 *   - The parent still sees the original data on all pages
 *   - The child sees original data on unmodified pages
 *   - The child sees its own data on modified (CoW-ed) pages
 *
 * This exercises compression of both unmodified pages that remain shared
 * through fork CoW and private pages created by child writes.
 */

#define NR_PAGES	512
#define COW_PAGES	128	/* child modifies these */
#define PATTERN_PARENT	0xAA
#define PATTERN_CHILD	0x55

static int child_fn(char *region, int pipe_fd)
{
	int i;
	char status;
	ssize_t ret;

	/*
	 * Modify the first COW_PAGES pages in the child.
	 * This triggers copy-on-write: the child gets private
	 * copies while the parent retains the original.
	 */
	for (i = 0; i < COW_PAGES * (int)PAGE_SIZE; i++)
		region[i] = PATTERN_CHILD;

	/* Signal parent that CoW writes are done */
	status = 1;
	ret = write(pipe_fd, &status, 1);
	if (ret != 1) {
		if (ret < 0)
			pr_perror("child: write to pipe");
		else
			pr_err("child: short pipe write: %zd of 1 byte\n", ret);
		return 1;
	}

	/* Wait for C/R */
	test_waitsig();

	/* Verify child's view after restore */
	for (i = 0; i < COW_PAGES * (int)PAGE_SIZE; i++) {
		if ((unsigned char)region[i] != PATTERN_CHILD) {
			fail("child: CoW page byte %d is 0x%02x, expected 0x%02x",
			     i, (unsigned char)region[i], PATTERN_CHILD);
			return 1;
		}
	}
	for (i = COW_PAGES * (int)PAGE_SIZE; i < NR_PAGES * (int)PAGE_SIZE; i++) {
		if ((unsigned char)region[i] != PATTERN_PARENT) {
			fail("child: unmodified page byte %d is 0x%02x, expected 0x%02x",
			     i, (unsigned char)region[i], PATTERN_PARENT);
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *region;
	pid_t pid;
	int pipe_fds[2];
	int i, status;
	char sync_byte;
	ssize_t ret;

	test_init(argc, argv);

	region = mmap(NULL, NR_PAGES * PAGE_SIZE,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	/* Fill all pages with parent pattern */
	memset(region, PATTERN_PARENT, NR_PAGES * PAGE_SIZE);

	if (pipe(pipe_fds)) {
		pr_perror("pipe");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		close(pipe_fds[0]);
		_exit(child_fn(region, pipe_fds[1]));
	}

	close(pipe_fds[1]);

	/* Wait for child to finish CoW writes */
	ret = read(pipe_fds[0], &sync_byte, 1);
	if (ret != 1) {
		if (ret < 0)
			pr_perror("parent: read from pipe");
		else
			pr_err("parent: short pipe read: %zd of 1 byte\n", ret);
		goto err;
	}
	close(pipe_fds[0]);

	test_daemon();
	test_waitsig();

	/* Verify parent's view: all pages must still have PATTERN_PARENT */
	for (i = 0; i < NR_PAGES * (int)PAGE_SIZE; i++) {
		if ((unsigned char)region[i] != PATTERN_PARENT) {
			fail("parent: byte %d is 0x%02x, expected 0x%02x",
			     i, (unsigned char)region[i], PATTERN_PARENT);
			goto err;
		}
	}

	/* Wake the child so it can verify its own pages and exit */
	kill(pid, SIGTERM);

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		goto err;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("child exited with status %d", status);
		goto err;
	}

	pass();
	return 0;

err:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 1;
}
