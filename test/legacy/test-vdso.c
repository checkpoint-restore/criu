#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
	int counter = 0;
	struct timeval tv;
	struct timezone tz;

	printf("%s pid %d\n", argv[0], getpid());

	while (1) {
		gettimeofday(&tv, &tz);
		printf("Pid: %10d time: %10li\n",
		       getpid(), tv.tv_sec);
		sleep(3);
	}

	return 0;
}
