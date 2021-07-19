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

const char *test_doc = "Test ghost with one hole in the middle";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

/* Buffer that is suitable for hole size */
#define BUFSIZE 4096
static unsigned char buf4k[BUFSIZE];

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#ifdef HEAD_HOLE
#define HH 1
#else
#define HH 0
#endif

#ifdef TAIL_HOLE
#define TH 1
#else
#define TH 0
#endif

#define DATA1_BLK   (HH)
#define DATA1_OFF   (DATA1_BLK * BUFSIZE)
#define DATA2_BLK   (HH + 2)
#define DATA2_OFF   (DATA2_BLK * BUFSIZE)
#define FILE_BLOCKS (TH + HH + 1 /* mid hole */ + 2 /* data */)
#define FILE_SIZE   (FILE_BLOCKS * BUFSIZE)

int main(int argc, char **argv)
{
	int fd;
	struct stat st;
	uint32_t crc;
	bool chk_hole = true;

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

	crc = ~0;
	datagen(buf4k, BUFSIZE, &crc);
	if (pwrite(fd, buf4k, BUFSIZE, DATA1_OFF) != BUFSIZE) {
		pr_perror("can't write data1");
		goto failed;
	}

	crc = ~0;
	datagen(buf4k, BUFSIZE, &crc);
	if (pwrite(fd, buf4k, BUFSIZE, DATA2_OFF) != BUFSIZE) {
		pr_perror("can't write data2");
		goto failed;
	}

	if (ftruncate(fd, FILE_SIZE)) {
		pr_perror("Can't fixup file size");
		goto failed;
	}

	if (lseek(fd, DATA1_OFF, SEEK_HOLE) != DATA1_OFF + BUFSIZE) {
		test_msg("Won't check for hole\n");
		chk_hole = false;
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

	test_msg("Blocks %u OK\n", FILE_BLOCKS);

	/* Data 1 */
	if (pread(fd, buf4k, BUFSIZE, DATA1_OFF) != BUFSIZE) {
		fail("pread1 fail");
		goto failed;
	}

	crc = ~0;
	if (datachk(buf4k, BUFSIZE, &crc)) {
		fail("datachk1 fail");
		goto failed;
	}

	test_msg("Data @%u OK\n", DATA1_BLK);

	/* Data 2 */
	if (pread(fd, buf4k, BUFSIZE, DATA2_OFF) != BUFSIZE) {
		fail("pread2 fail");
		goto failed;
	}

	crc = ~0;
	if (datachk(buf4k, BUFSIZE, &crc)) {
		fail("datachk2 fail");
		goto failed;
	}

	test_msg("Data @%u OK\n", DATA2_BLK);

	/* Hole */
	if (chk_hole) {
#ifdef HEAD_HOLE
		if (lseek(fd, 0, SEEK_HOLE) != 0) {
			fail("hh not found");
			goto failed;
		}

		test_msg("Head hole OK\n");
#endif

		if (lseek(fd, DATA1_OFF, SEEK_HOLE) != DATA1_OFF + BUFSIZE) {
			fail("mh not found");
			goto failed;
		}

		test_msg("Mid hole OK\n");

#ifdef TAIL_HOLE
		if (lseek(fd, DATA2_OFF, SEEK_HOLE) != DATA2_OFF + BUFSIZE) {
			fail("tail hole not found");
			goto failed;
		}

		test_msg("Tail hole OK\n");
#endif
	}

	close(fd);
	pass();
	return 0;

failed:
	close(fd);
	return 1;
}
