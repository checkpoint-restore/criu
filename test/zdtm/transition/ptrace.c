#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "zdtmtst.h"

const char *test_doc = "Tests that ptraced thread do not escape from tracing";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

#define NR_THREADS 2
unsigned int nr_threads = NR_THREADS;
TEST_OPTION(nr_threads, uint, "Number of threads", 0);

static void *thread(void *arg)
{
	*(int *)arg = syscall(SYS_gettid);
	while (1)
		sleep(1);
	return NULL;
}

int main(int argc, char **argv)
{
	int pid, status, i, stopped;
#define PT_REGS_SIZE  4096 /* big enough for any arch */
#define PT_REGS_ALIGN 16   /* big enough for any arch */
	char regs[PT_REGS_SIZE] __attribute__((aligned(PT_REGS_ALIGN)));

	int *pids;

	test_init(argc, argv);

	pids = (int *)mmap(NULL, sizeof(int) * nr_threads, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (pids == MAP_FAILED) {
		pr_perror("Can't map");
		exit(1);
	}

	memset(pids, 0, sizeof(int) * nr_threads);

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	} else if (pid == 0) {
		pthread_t pt[nr_threads];

		for (i = 0; i < nr_threads - 1; i++) {
			if (pthread_create(&pt[i], NULL, thread, pids + i)) {
				pr_perror("Can't make thread");
				goto out_th;
			}
		}
		thread(pids + i);
	out_th:
		for (i--; i >= 0; i--) {
			pthread_kill(pt[i], SIGKILL);
			pthread_join(pt[i], NULL);
		}
		return 0;
	}

	for (i = 0; i < nr_threads; i++) {
		while (pids[i] == 0)
			sched_yield();
		if (ptrace(PTRACE_ATTACH, pids[i], (char *)1, NULL) == -1) {
			pr_perror("Can't attach");
			goto out_pt;
		}
	}

	test_daemon();

	while (test_go()) {
		for (i = 0; i < nr_threads; i++)
			if (pids[i])
				break;
		if (i == nr_threads)
			break;
		stopped = wait4(-1, &status, __WALL, NULL);
		if (stopped == -1) {
			pr_perror("Can't wait");
			break;
		}

		if (WIFSTOPPED(status)) {
			if (ptrace(PTRACE_GETSIGINFO, stopped, NULL, regs)) {
				/* FAIL */
				fail("Ptrace won't work");
				break;
			}

			for (i = 0; i < nr_threads; i++)
				if (pids[i] == stopped)
					break;
			if (i == nr_threads)
				continue;

			pids[i] = 0;
			ptrace(PTRACE_DETACH, stopped, (char *)1, NULL);
			ptrace(PTRACE_CONT, stopped, (char *)1, NULL);
			continue;
		}
	}
	test_waitsig();
	pass();
out_pt:
	kill(pid, SIGKILL);
	wait(NULL);
out:
	munmap(pids, sizeof(int) * nr_threads);
	return 0;
}
