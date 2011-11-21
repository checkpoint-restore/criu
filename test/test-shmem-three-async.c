#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sched.h>

static void *map1;
static void *map2;

int main(int argc, char *argv[])
{
	pid_t pid;

	printf("%s pid %d\n", argv[0], getpid());

	map1 = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	map2 = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (map1 == MAP_FAILED || map2 == MAP_FAILED) {
		printf("%6d: mmap failed\n", getpid());
		return 0;
	}

	memset(map1, '-', 22);
	((char *)map1)[22] = 0;

	memset(map2, '+', 22);
	((char *)map1)[22] = 0;

	printf("%6d: Initial  shmem1 pattern '%s'\n", getpid(), (char *)map1);

	pid = fork();
	if (pid == -1) {
		printf("fork1 failed\n");
		return 1;
	} else if (pid == 0) {
		int cnt = 0;

		pid = fork();
		if (pid == -1) {
			printf("fork2 failed\n");
			exit(1);
		} else if (pid == 0) {
			int num = 0;
			while(1) {
				printf("%6d: Observed shmem2 pattern '%s'\n", getpid(), (char *)map2);
				sprintf(map2, "shared-mem2-%010d", num);
				sleep(1);
				num += 2;
			}
		}

		cnt = -1;
		while(1) {
			cnt += 2;
			printf("%6d: Observed shmem1 pattern '%s'\n", getpid(), (char *)map1);
			sprintf(map1, "shared-mem1-%010d", cnt);
			sleep(1);
		}
	} else {
		while(1) {
			printf("%6d: Observed shmem1 pattern '%s'\n", getpid(), (char *)map1);
			printf("%6d: Observed shmem2 pattern '%s'\n", getpid(), (char *)map2);
			sleep(1);
		}
	}

	return 0;
}
