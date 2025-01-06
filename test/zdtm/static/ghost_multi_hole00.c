#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Test ghost with a lot of holes(every 8K length contains only 4K data)";
const char *test_author = "Liang-Chun Chen <featherclc@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

/* Buffer that is suitable for hole size */
#define BUFSIZE 4096
static unsigned char buf4k[BUFSIZE];

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#define FILE_SIZE (1 << 23) /* 8Mb */

#define FILE_INTERVAL (1 << 13) /* 8Kb */

int main(int argc, char **argv)
{
	int fd, off;
	struct stat st;
	uint32_t crc;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

	for (off = 0; off < FILE_SIZE; off += FILE_INTERVAL) {
		crc = ~0;
		datagen(buf4k, BUFSIZE, &crc);
		if (pwrite(fd, &buf4k, BUFSIZE, off) != BUFSIZE) {
			perror("pwrite");
			goto failed;
		}

		/*
		* In some file system, such as xfs,
		* only pwrite might not able to create highly sparse file,
		* so we need to forcibly allocate hole inside the file.
		*/
		if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off + BUFSIZE, BUFSIZE)) {
			perror("fallocate");
			goto failed;
		}
	}

	if (ftruncate(fd, FILE_SIZE)) {
		pr_perror("Can't fixup file size");
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &st) < 0) {
		fail("can't stat after");
		goto failed;
	}

	if (st.st_size != FILE_SIZE) {
		fail("file size changed to %ld", (long)st.st_size);
		goto failed;
	}

	test_msg("Size %u OK\n", FILE_SIZE);

	/* Data*/
	for (off = 0; off < FILE_SIZE; off += FILE_INTERVAL) {
		if (pread(fd, buf4k, BUFSIZE, off) != BUFSIZE) {
			fail("pread failed @ %u", off / FILE_INTERVAL);
			goto failed;
		}

		crc = ~0;
		if (datachk(buf4k, BUFSIZE, &crc)) {
			fail("datachk failed @ %u", off / FILE_INTERVAL);
			goto failed;
		}

		test_msg("Data @%du OK\n", off / FILE_INTERVAL);
	}

	/* Hole */
	for (off = 0; off < FILE_SIZE; off += FILE_INTERVAL) {
		if (lseek(fd, off, SEEK_HOLE) != off + BUFSIZE) {
			fail("failed to find hole @ %u", off / FILE_SIZE);
			goto failed;
		}
		test_msg("Hole @%du OK\n", off / FILE_INTERVAL);
	}

	close(fd);
	pass();
	return 0;

failed:
	close(fd);
	return 1;
}
