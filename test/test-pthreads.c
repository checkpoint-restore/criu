/*
 * A simple testee program with threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>

#define __NR_arch_prctl		158

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1)
		: "rax", "rdi", "rsi", "memory");
	return ret;
}

static long sys_arch_prctl(int code, void *addr)
{
	return syscall2(__NR_arch_prctl, code, (unsigned long)addr);
}

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static int counter;
static int thread_counter = 1;

static __thread int tls_data;

static void pr_fsgs_base(char *name)
{
	unsigned long fsgs_base = -1ul;
	int ret;

	ret = sys_arch_prctl(ARCH_GET_FS, &fsgs_base);

	printf("%8d (%15s): (%2d) fsgs_base %8lx\n",
	       getpid(), name, ret, fsgs_base);

	ret = sys_arch_prctl(ARCH_GET_GS, &fsgs_base);

	printf("%8d (%15s): (%2d) fsgs_base %8lx\n",
	       getpid(), name, ret, fsgs_base);
}

static void *ff1(void *arg)
{
	void *map_unreadable = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pid_t pid;
	(void)map_unreadable;

	tls_data = thread_counter++;

	pr_fsgs_base("thr3");

	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid == 0) {
		while (1) {
			pthread_mutex_lock(&mtx);

			counter++;
			printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
			       getpid(), "thr3-ch", counter, tls_data);

			pthread_mutex_unlock(&mtx);
			sleep(5);
		}
	}

	while (1) {
		pthread_mutex_lock(&mtx);

		counter++;
		printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
		       getpid(), "thr3", counter, tls_data);

		pthread_mutex_unlock(&mtx);
		sleep(5);
	}

	return NULL;
}

static void *f1(void *arg)
{
	const char name[] = "f1-file";
	pthread_t th;
	pid_t pid;
	int fd;
	void *map_unreadable = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)map_unreadable;

	unlink(name);
	fd = open(name, O_CREAT, 0644);
	if (fd >= 0)
		write(fd, name, sizeof(name));

	if (pthread_create(&th, NULL, &ff1, NULL))
		perror("Cant create thread");

	tls_data = thread_counter++;

	pr_fsgs_base("thr1");

	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid == 0) {
		while (1) {
			pthread_mutex_lock(&mtx);

			counter++;
			printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
				getpid(), "thr1-ch", counter, tls_data);

			pthread_mutex_unlock(&mtx);
			sleep(2);
		}
	}

	while (1) {
		pthread_mutex_lock(&mtx);

		counter++;
		printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
		       getpid(), "thr1", counter, tls_data);

		pthread_mutex_unlock(&mtx);
		sleep(2);
	}

	return NULL;
}

static void *f2(void *arg)
{
	void *map_unreadable = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pid_t pid;
	(void)map_unreadable;

	tls_data = thread_counter++;

	pr_fsgs_base("thr2");

	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid == 0) {
		while (1) {
			pthread_mutex_lock(&mtx);

			counter--;
			printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
			       getpid(), "thr2-ch", counter, tls_data);

			pthread_mutex_unlock(&mtx);
			sleep(3);
		}
	}

	while (1) {
		pthread_mutex_lock(&mtx);

		counter--;
		printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
		       getpid(), "thr2", counter, tls_data);

		pthread_mutex_unlock(&mtx);
		sleep(3);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t th1, th2;
	int rc1, rc2;
	pid_t pid;

	printf("%s pid %d\n", argv[0], getpid());

	tls_data = thread_counter++;

	pr_fsgs_base("main");

	printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
	       getpid(), "main", counter, tls_data);

	rc1 = pthread_create(&th1, NULL, &f1, NULL);
	rc2 = pthread_create(&th2, NULL, &f2, NULL);

	if (rc1 | rc2)
		exit(1);

	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid == 0) {
		while (1) {
			printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
			       getpid(), "main-child", counter, tls_data);
			sleep(2);
		}
	}

	while (1) {
		printf("%8d (%15s): Counter value: %4d tls_data = %4d\n",
		       getpid(), "main", counter, tls_data);
		sleep(2);
	}

	pthread_join(th1, NULL);
	pthread_join(th2, NULL);

	exit(0);
}
