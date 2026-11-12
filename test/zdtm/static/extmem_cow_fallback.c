#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Provider-backed parent with a normally restored child";
const char *test_author = "Dan Feigin <dfeigin@nvidia.com>";

static int check_bytes(const uint8_t *memory, size_t length, uint8_t byte)
{
	size_t i;

	for (i = 0; i < length; i++)
		if (memory[i] != byte)
			return -1;
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t *memory, *private;
	char filename[] = "extmem-cow-file.XXXXXX";
	task_waiter_t waiter;
	pid_t child;
	int fd, status;

	test_init(argc, argv);
	task_waiter_init(&waiter);
	memory = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	fd = mkstemp(filename);
	if (memory == MAP_FAILED || fd < 0 || ftruncate(fd, PAGE_SIZE)) {
		pr_perror("allocate memory");
		return 1;
	}
	private = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (private == MAP_FAILED) {
		pr_perror("map file");
		return 1;
	}
	memset(memory, 0x5a, 2 * PAGE_SIZE);
	memset(private, 0x77, PAGE_SIZE);
	close(fd);

	child = test_fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}
	if (!child) {
		memset(memory, 0x33, PAGE_SIZE);
		if (madvise(memory + PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED))
			return 1;
		task_waiter_complete(&waiter, 1);
		test_waitsig();
		return check_bytes(memory, PAGE_SIZE, 0x33) ||
		       check_bytes(memory + PAGE_SIZE, PAGE_SIZE, 0) ||
		       check_bytes(private, PAGE_SIZE, 0x77);
	}
	task_waiter_wait4(&waiter, 1);
	test_daemon();
	test_waitsig();

	kill(child, SIGTERM);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
	    check_bytes(memory, 2 * PAGE_SIZE, 0x5a) ||
	    check_bytes(private, PAGE_SIZE, 0x77)) {
		fail("provider parent or fallback child memory changed");
		return 1;
	}
	task_waiter_fini(&waiter);
	unlink(filename);
	pass();
	return 0;
}
