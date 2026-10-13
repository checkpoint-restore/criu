#include <stdio.h>
#include <unistd.h>

int main(void)
{
	int i = 0;

	/* Not to be a session leader outside of its pid namespace. */
	setsid();
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("Process started in user namespace (pid %d)\n", getpid());
	while (1) {
		printf("Running %d...\n", i++);
		sleep(1);
	}
	return 0;
}
