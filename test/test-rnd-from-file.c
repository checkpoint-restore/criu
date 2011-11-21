#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	const char fname_rnd[] = "random-data.o"; /* so make clean drops it */
	const int limit = 10;
	int counter, fd, rnd;

	printf("%s pid %d\n", argv[0], getpid());

	unlink((char *)fname_rnd);

	fd = open(fname_rnd, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		perror("Can't open file");
		return fd;
	}

	counter = 0;
	while (counter++ < limit) {
		rnd = rand();
		write(fd, &rnd, sizeof(rnd));
	}

	counter = 0;
	while (1) {
		lseek(fd, 0, SEEK_SET);
		while (counter++ < limit) {
			read(fd, &rnd, sizeof(rnd));
			printf("Pid: %10d Rnd: %10d\n",
			       getpid(), rnd);
			sleep(3);
		}
	}

	return 0;
}
