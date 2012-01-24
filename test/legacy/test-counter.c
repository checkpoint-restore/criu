#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>

int main(int argc, char *argv[])
{
	int counter = 0;

	printf("%s pid %d\n", argv[0], getpid());

	while (1) {
		printf("Pid: %10d Counter: %10d\n",
		       getpid(), counter++);
		sleep(3);
	}

	return 0;
}
