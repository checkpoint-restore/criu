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

static void *map;

int main(int argc, char *argv[])
{
	pid_t pid;

	printf("%s pid %d\n", argv[0], getpid());

	map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (map	== MAP_FAILED) {
		printf("mmap failed\n");
		return 0;
	}

	memset(map, '-', 32);
	((char *)map)[32] = 0;

	printf("%d: shmem '%s'\n", getpid(), (char *)map);

	pid = fork();
	if (pid == -1) {
		printf("fork failed\n");
		return 1;
	}

	if (pid == 0) {
		int cnt = 0;
		while(1) {
			printf("%d: shmem '%s'\n", getpid(), (char *)map);
			sprintf(map, "shared-mem-%d", cnt++);
			sleep(5);
		}
	} else {
		while(1) {
			printf("%d: shmem '%s'\n", getpid(), (char *)map);
			sleep(3);
		}
	}

	return 0;
}
