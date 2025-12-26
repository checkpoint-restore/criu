#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stddef.h>

#include "zdtmtst.h"

const char *test_doc = "Verify robust futex list cleanup survives C/R";
const char *test_author = "Imranullah Khan <imranullahkhann2004@gmail.com>";

struct shared_state {
	struct robust_list_head head;
	struct robust_list entry;
	int futex;
	task_waiter_t waiter;
};

static pid_t __gettid(void)
{
	return syscall(__NR_gettid);
}

void *worker_fn(void *arg)
{
	struct shared_state *s = arg;

	s->entry.next = &s->entry;
	s->head.list.next = &s->entry;
	s->head.futex_offset =
		offsetof(struct shared_state, futex) -
		offsetof(struct shared_state, entry);
	s->head.list_op_pending = NULL;

	if (syscall(__NR_set_robust_list, &s->head, sizeof(s->head))) {
		fail("set_robust_list failed");
		return NULL;
	}

	s->futex = __gettid();

	test_msg("Worker %d acquired futex\n", s->futex);

	task_waiter_complete(&s->waiter, 1);

	task_waiter_wait4(&s->waiter, 2);

	test_msg("Worker exiting while holding futex\n");

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread;
	struct shared_state *s;

	test_init(argc, argv);

	s = mmap(NULL, sizeof(*s),
		 PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (s == MAP_FAILED) {
		fail("mmap failed");
		return 1;
	}

	s->futex = 0;
	task_waiter_init(&s->waiter);

	if (pthread_create(&thread, NULL, worker_fn, s)) {
		fail("pthread_create failed");
		return 1;
	}

	task_waiter_wait4(&s->waiter, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&s->waiter, 2);
	pthread_join(thread, NULL);

	test_msg("Post-exit futex value: 0x%x\n", s->futex);

	if (s->futex & FUTEX_OWNER_DIED)
		pass();
	else
		fail("OWNER_DIED not set - robust futex cleanup failed");

	munmap(s, sizeof(*s));
	return 0;
}
