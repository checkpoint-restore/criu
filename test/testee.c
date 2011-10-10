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

static int do_child(void *arg)
{
	printf("do_child pid: %d\n", getpid());

	void *stack, *mmap_anon;

	stack = mmap(0, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, 0, 0);
	if (stack == MAP_FAILED)
		return -1;

	mmap_anon = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mmap_anon == MAP_FAILED)
		return -1;

	while (1)
		sleep(6);

	return 0;
}

static int run_clone(void)
{
	pid_t pid = 0;
	int ret = 0;
	void *stack, *mmap_anon;

	stack = mmap(0, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, 0, 0);
	if (stack == MAP_FAILED)
		return -1;

	mmap_anon = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mmap_anon == MAP_FAILED)
		return -1;

	stack += 4 * 4096;

	ret = clone(do_child, stack, CLONE_FS, NULL, NULL, NULL, &pid);
	if (ret < 0)
		perror("Failed clone");

	printf("run_clone: %d stack: %p mmap_anon: %p ret %d\n",
	       pid, stack, mmap_anon, ret);

	if (stack == MAP_FAILED)
		return -1;

	mmap_anon = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mmap_anon == MAP_FAILED)
		return -1;

	stack += 4 * 4096;

	ret = clone(do_child, stack, CLONE_FS | CLONE_FILES | CLONE_VM, NULL, NULL, NULL, &pid);
	if (ret < 0)
		perror("Failed clone");

	printf("run_clone: %d stack: %p mmap_anon: %p ret %d\n",
	       pid, stack, mmap_anon, ret);

	return ret;
}

int main(int argc, char *argv[])
{
	int pipefd[2];
	int fd_shared, fd_private;
	const char data_mark[] = "This is a data_mark marker";
	void *mmap_shared, *mmap_private, *mmap_anon, *map_unreadable;
	void *mmap_anon_sh;
	const char sep[] = "----------";
	pid_t pid, child;
	char suided_path[128];
	int i;

	(void)data_mark;

	printf("%s pid %d\n", argv[0], getpid());

	if (pipe(pipefd)) {
		perror("Can't create pipe");
		goto err;
	}

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
	mmap_anon	= mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	map_unreadable	= mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mmap_anon_sh	= mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

	if (mmap_shared		== MAP_FAILED ||
	    mmap_private	== MAP_FAILED ||
	    mmap_anon		== MAP_FAILED ||
	    mmap_anon_sh	== MAP_FAILED ||
	    map_unreadable	== MAP_FAILED) {

		perror("mmap failed");
		goto err;
	}

	snprintf(suided_path, sizeof(suided_path),
		 "/proc/%d/map_files/%lx-%lx",
		 getpid(), (long)mmap_shared,
		 (long)mmap_shared + 0x1000);

	strcpy((char *)mmap_shared,	sep);
	strcpy((char *)mmap_private,	sep);
	strcpy((char *)mmap_anon,	sep);
	strcpy((char *)map_unreadable,	sep);
	strcpy((char *)mmap_anon_sh,	sep);

	for (i = 64; i < 128; i++) {
		((char *)mmap_shared)[i]	=   0 + i;
		((char *)mmap_private)[i]	=  64 + i;
		((char *)mmap_anon)[i]		= 128 + i;
		((char *)mmap_anon_sh)[i]	= 128 + i;
		((char *)map_unreadable)[i]	= 190 + i;
	}

	if (mprotect(map_unreadable, 1024, PROT_NONE)) {
		perror("mprotect failed");
		goto err;
	}

	asm volatile("" ::: "memory");

	fsync(fd_shared);
	fsync(fd_private);

	close(fd_shared);

       if (argc > 1) {

                printf("my-uid: %d\n", getuid());
                setuid(atoi(argv[1]));
                printf("my-uid: %d\n", getuid());
        }

        fd_shared = open(suided_path, O_RDWR, 0600);
        printf("fd_shared for O_RDWR: %d\n", fd_shared);
        if (fd_shared >= 0) {
                write(fd_shared, "aaaa", sizeof("aaaa"));
                close(fd_shared);
        }

        fd_shared = open(suided_path, O_TRUNC, 0600);
        printf("fd_shared for O_TRUNC: %d\n", fd_shared);
        if (fd_shared >= 0) {
                printf("tunc: %d\n", ftruncate(fd_shared, 512));
                close(fd_shared);
        }

        fd_shared = open(suided_path, O_RDONLY, 0600);
        printf("fd_shared for O_RDONLY: %d\n", fd_shared);
        if (fd_shared >= 0)
                close(fd_shared);

	sync();
	asm volatile("" ::: "memory");

	pid = fork();
	if (pid == -1)
		goto err;

	if (pid == 0) {
		long buf;
		child = fork();
		if (child == -1)
			goto err;
		if (child == 0) {
			printf("first child pid: %d\n", getpid());
			while (read(pipefd[0], &buf, sizeof(buf)) > 0)
				sleep(3);
			*(unsigned long *)mmap_anon_sh = 0x11111111;
			while (1) {
				printf("ping: %d\n", getpid());
				sleep(8);
			}
		} else {
			*(unsigned long *)mmap_anon_sh = 0x22222222;
			printf("first parent pid: %d\n", getpid());
//			run_clone();
			while (1) {
				printf("ping: %d\n", getpid());
				sleep(9);
			}
		}
	} else {
		long buf = 0xdeadbeef;
		while (1) {
			float res = 0.9;
			*(unsigned long *)mmap_anon_sh = 0x33333333;
			printf("ping: %d %f\n", getpid(), res + (float)(unsigned long)mmap_anon_sh);
			write(pipefd[1], &buf, sizeof(buf));
			sleep(10);
		}
	}

err:
	/* resources are released by kernel */
	return 0;
}
