/*
 * A simple testee program
 */

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

int main(int argc, char *argv[])
{
	int fd_shared, fd_private;
	const char data_mark[] = "This is a data_mark marker";
	void *mmap_shared, *mmap_private, *mmap_anon, *map_unreadable;
	const char sep[] = "----------";
	pid_t pid, child;
	int i;

	printf("%s pid %d\n", argv[0], getpid());

	fd_shared = open("testee-shared.img", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd_shared < 0) {
		perror("Can't open fd_shared file");
		goto err;
	}

	fd_private = open("testee-private.img", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd_private < 0) {
		perror("Can't open fd_private file");
		goto err;
	}

	if (lseek(fd_shared, 1024, SEEK_SET) == -1 ||
	    lseek(fd_private, 1024, SEEK_SET) == -1) {
		perror("Can't llsek");
		goto err;
	}

	write(fd_shared, "", 1);
	write(fd_private, "", 1);

	mmap_shared	= mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd_shared, 0);
	mmap_private	= mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd_private, 0);

	if (mmap_shared		== MAP_FAILED ||
	    mmap_private	== MAP_FAILED) {

		perror("mmap failed");
		goto err;
	}

	strcpy((char *)mmap_shared,	sep);
	strcpy((char *)mmap_private,	sep);

	for (i = 64; i < 128; i++) {
		((char *)mmap_shared)[i]	=   0 + i;
		((char *)mmap_private)[i]	=  64 + i;
	}

	fsync(fd_shared);
	fsync(fd_private);

	close(fd_shared);
	fsync(fd_private);

	unlink("testee-shared.img");
	unlink("testee-private.img");

	for (i = 64; i < 128; i++) {
		((char *)mmap_shared)[i]	=   0 + i;
		((char *)mmap_private)[i]	=  64 + i;
	}

	msync(mmap_shared, 1024, MS_SYNC);
	msync(mmap_private, 1024, MS_SYNC);

	while (1)
		sleep(1);

err:
	/* resources are released by kernel */
	return 0;
}
