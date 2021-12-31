#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "zdtmtst.h"

const char *test_doc = "Test MAP_HUGETLB mapping in parent-child relationship processes";
const char *test_author = "Bui Quang Minh <minhquangbui99@gmail.com>";

#define MEM_SIZE (2UL * (1UL << 20)) /* 2MB */

int main(int argc, char **argv)
{
	void *p1, *p2, *s1;
	task_waiter_t t;
	pid_t pid;
	uint32_t crc, tmp_crc;
	int status;

	test_init(argc, argv);
	task_waiter_init(&t);

	p1 = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (p1 == MAP_FAILED) {
		pr_perror("Map failed");
		return 1;
	}

	p2 = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (p2 == MAP_FAILED) {
		pr_perror("Map failed");
		return 1;
	}

	s1 = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (s1 == MAP_FAILED) {
		pr_perror("Map failed");
		return 1;
	}

	crc = ~0;
	datagen(p1, MEM_SIZE, &crc);
	crc = ~0;
	datagen(p2, MEM_SIZE, &crc);
	tmp_crc = crc;

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return 1;
	}

	if (pid == 0) {
		crc = ~0;
		datagen(p2, MEM_SIZE, &crc);
		tmp_crc = crc;
		crc = ~0;
		datagen(s1, MEM_SIZE, &crc);

		task_waiter_complete(&t, 1);
		test_waitsig();

		crc = ~0;
		if (datachk(p1, MEM_SIZE, &crc)) {
			fail("Data mismatch");
			return 1;
		}

		crc = ~0;
		if (datachk(p2, MEM_SIZE, &crc)) {
			fail("Data mismatch");
			return 1;
		}

		if (crc != tmp_crc) {
			fail("Data mismatch");
			return 1;
		}

		crc = ~0;
		if (datachk(s1, MEM_SIZE, &crc)) {
			fail("Data mismatch");
			return 1;
		}

		return 0;
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	wait(&status);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			goto err;
	} else {
		goto err;
	}

	crc = ~0;
	if (datachk(p1, MEM_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}

	crc = ~0;
	if (datachk(p2, MEM_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}

	if (crc != tmp_crc) {
		fail("Data mismatch");
		return 1;
	}

	crc = ~0;
	if (datachk(s1, MEM_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}

	pass();

	return 0;
err:
	if (waitpid(-1, NULL, WNOHANG) == 0) {
		kill(pid, SIGTERM);
		wait(NULL);
	}
	return 1;
}