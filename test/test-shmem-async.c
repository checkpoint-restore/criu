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
		printf("%6d: mmap failed\n", getpid());
		return 0;
	}

	memset(map, '-', 21);
	((char *)map)[21] = 0;

	printf("%6d: Initial  shmem pattern '%s'\n", getpid(), (char *)map);

	pid = fork();
	if (pid == -1) {
		printf("fork failed\n");
		return 1;
	}

	if (pid == 0) {
		int cnt = 0;
		while(1) {
			printf("%6d: Observed shmem pattern '%s'\n", getpid(), (char *)map);
			sprintf(map, "shared-mem-%010d", cnt++);
			sleep(1);
		}
	} else {
		while(1) {
			printf("%6d: Observed shmem pattern '%s'\n", getpid(), (char *)map);
			sleep(3);
		}
	}

	return 0;
}
