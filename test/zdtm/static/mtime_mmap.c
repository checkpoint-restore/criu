#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "file mmaped for write and being written should change mtime\n"
		       "and be migrated with correct new data";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define FILE_SIZE (16 * 1024)

int main(int argc, char **argv)
{
	int fd;
	char buf[FILE_SIZE];
	size_t count;
	int i;
	char *ptr;
	struct stat fst;
	time_t mtime_old, mtime_new;
	time_t ctime_old, ctime_new;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	/* initialization */
	count = sizeof(buf);
	memset(buf, 1, count);
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("failed to write %s", filename);
		exit(1);
	}

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get %s file info", filename);
		goto failed;
	}

	ptr = (char *)mmap(NULL, count, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		pr_perror("mmap() failed");
		goto failed;
	}

	mtime_old = fst.st_mtime;
	ctime_old = fst.st_ctime;
	sleep(2);

	for (i = 0; i < count; i++)
		ptr[i]++;

	if (munmap(ptr, count)) {
		pr_perror("munmap failed");
		goto failed;
	}

	if (fstat(fd, &fst) < 0) {
		pr_perror("fstat(%s) failed", filename);
		goto failed;
	}

	mtime_new = fst.st_mtime;
	/* time of last modification */
	if (mtime_new <= mtime_old) {
		fail("mtime %ld wasn't updated on mmapped %s file", mtime_new, filename);
		goto failed;
	}

	ctime_new = fst.st_ctime;
	/* time of last status change */
	if (ctime_new <= ctime_old) {
		fail("time of last status change of %s file wasn't changed", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get %s file info", filename);
		goto failed;
	}

	/* time of last modification */
	if (fst.st_mtime != mtime_new) {
		fail("After migration, mtime changed to %ld", fst.st_mtime);
		goto failed;
	}

	pass();
	unlink(filename);
	close(fd);
	return 0;
failed:
	return 1;
}
