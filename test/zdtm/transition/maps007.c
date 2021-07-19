
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <asm/unistd.h>

#include "zdtmtst.h"
#include "lock.h"

#define MAP_SIZE (1UL << 20)
#define MEM_SIZE (1UL << 29)

const char *test_doc = "create random mappings and touch memory";

int sys_process_vm_readv(pid_t pid, void *addr, void *buf, int size)
{
	struct iovec lvec = { .iov_base = buf, .iov_len = size };
	struct iovec rvec = { .iov_base = addr, .iov_len = size };
	/* workaround bug in glibc with sixth argument of syscall */
	char nop[PAGE_SIZE];

	memset(nop, 0, sizeof(nop));

	return syscall(__NR_process_vm_readv, pid, &lvec, 1, &rvec, 1, 0);
}

/* The child follows the parents two steps behind. */
#define MAX_DELTA 1000
int main(int argc, char **argv)
{
	void *start, *end, *p;
	pid_t child;
	struct {
		futex_t delta;
		futex_t stop;
	} * shm;
	uint32_t v;
	unsigned long long count = 0;
	int i;

	test_init(argc, argv);

	/* shared memory for synchronization */
	shm = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (shm == MAP_FAILED)
		return -1;

	/* allocate workspace */
	start = mmap(NULL, MEM_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (start == MAP_FAILED)
		return -1;

	test_msg("%p-%p\n", start, start + MEM_SIZE);

	end = start + MEM_SIZE;

	v = 0;
	futex_set(&shm->delta, v);
	futex_set(&shm->stop, 0);

	child = fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}

	while (1) {
		void *ret;
		unsigned long size;
		int prot = PROT_NONE;

		if (child) {
			if (!test_go())
				break;
			futex_wait_while_gt(&shm->delta, 2 * MAX_DELTA);
			futex_inc_and_wake(&shm->delta);
		} else {
			if (!futex_get(&shm->stop))
				/* shm->delta must be always bigger than MAX_DELTA */
				futex_wait_while_lt(&shm->delta, MAX_DELTA + 2);
			else if (count % 100 == 0)
				test_msg("count %llu delta %d\n", count, futex_get(&shm->delta)); /* heartbeat */

			if (futex_get(&shm->stop) && atomic_get(&shm->delta.raw) == MAX_DELTA)
				break;
			futex_dec_and_wake(&shm->delta);
		}

		count++;
		if (child && count == MAX_DELTA + 1)
			test_daemon();

		p = start + ((lrand48() * PAGE_SIZE) % MEM_SIZE);
		size = lrand48() * PAGE_SIZE;
		size %= (end - p);
		size %= MAP_SIZE;
		if (size == 0)
			size = PAGE_SIZE;

		if (lrand48() % 2)
			prot |= PROT_READ;
		if (lrand48() % 2)
			prot |= PROT_EXEC;
		if (lrand48() % 2)
			prot |= PROT_WRITE;

		ret = mmap(p, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (ret == MAP_FAILED) {
			pr_perror("%p-%p", p, p + size);
			goto err;
		}

		if (!(prot & PROT_WRITE))
			continue;

		for (i = 0; i < lrand48() % 50; i++) {
			char *t = p + (lrand48() * PAGE_SIZE) % (size);
			t[0] = lrand48();
		}
	}
	test_msg("count %llu\n", count);

	if (child == 0) {
		if (!test_go())
			pr_perror("unexpected state");
		futex_set_and_wake(&shm->stop, 2);
		test_waitsig();
		return 0;
	} else {
		int readable = 0, status = -1;

		/* stop the child */
		futex_set(&shm->stop, 1);
		futex_add_and_wake(&shm->delta, MAX_DELTA);
		/* wait until the child will be in the same point */
		futex_wait_until(&shm->stop, 2);

		/* check that child and parent have the identical content of memory */
		for (p = start; p < end; p += PAGE_SIZE) {
			char rbuf[PAGE_SIZE], lbuf[PAGE_SIZE];
			int rret, lret;

			lret = sys_process_vm_readv(getpid(), p, lbuf, PAGE_SIZE);
			rret = sys_process_vm_readv(child, p, rbuf, PAGE_SIZE);
			if (rret != lret) {
				pr_perror("%p %d %d", p, lret, rret);
				goto err;
			}
			if (lret < 0)
				continue;
			readable++;
			if (memcmp(rbuf, lbuf, PAGE_SIZE)) {
				pr_perror("%p", p);
				goto err;
			}
		}
		test_msg("readable %d\n", readable);
		kill(child, SIGTERM);
		wait(&status);
		if (status != 0) {
			pr_perror("Non-zero exit code: %d", status);
			goto err;
		}
		pass();
	}

	return 0;
err:
	kill(child, SIGSEGV);
	*((volatile int *)0) = 0;
	return 1;
}
