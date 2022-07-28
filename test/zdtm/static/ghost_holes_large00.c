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

const char *test_doc = "Test ghost with one large hole(1GiB) in the middle";
const char *test_author = "Liang-Chun Chen <featherclc@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

/* Buffer that is suitable for data size */
#ifdef LIMIT
#define BUFSIZE 1024 * 1024
#else
#define BUFSIZE 4096
#endif
static unsigned char buf[BUFSIZE];

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#define DATA1_OFF 0
#define HOLE_SIZE (1LL * 1 * 1024 * 1024 * 1024)
#define DATA2_OFF (BUFSIZE + HOLE_SIZE)
#define FILE_SIZE (2 * BUFSIZE + HOLE_SIZE)
#define ST_UNIT	  512

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
	datagen(buf, BUFSIZE, &crc);
	if (pwrite(fd, buf, BUFSIZE, DATA1_OFF) != BUFSIZE) {
		pr_perror("can't write data1");
		goto failed;
	}

	crc = ~0;
	datagen(buf, BUFSIZE, &crc);
	if (pwrite(fd, buf, BUFSIZE, DATA2_OFF) != BUFSIZE) {
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

	test_msg("file size OK\n");

	if (st.st_blocks * ST_UNIT != 2 * BUFSIZE) {
		fail("actual file size changed to %ld", (long)st.st_blocks * ST_UNIT);
		goto failed;
	}

	test_msg("actual file size OK\n");

	/* Data 1 */
	if (pread(fd, buf, BUFSIZE, DATA1_OFF) != BUFSIZE) {
		fail("pread1 fail");
		goto failed;
	}

	crc = ~0;
	if (datachk(buf, BUFSIZE, &crc)) {
		fail("datachk1 fail");
		goto failed;
	}

	test_msg("Data1 OK\n");

	/* Data 2 */
	if (pread(fd, buf, BUFSIZE, DATA2_OFF) != BUFSIZE) {
		fail("pread2 fail");
		goto failed;
	}

	crc = ~0;
	if (datachk(buf, BUFSIZE, &crc)) {
		fail("datachk2 fail");
		goto failed;
	}

	test_msg("Data2 OK\n");

	/* Hole */
	if (chk_hole) {
		if (lseek(fd, DATA1_OFF, SEEK_HOLE) != DATA1_OFF + BUFSIZE) {
			fail("Begin of mid hole not found");
			goto failed;
		}
		if (lseek(fd, DATA1_OFF + BUFSIZE, SEEK_DATA) != DATA2_OFF) {
			fail("End of mid hole not found");
			goto failed;
		}
		test_msg("Mid hole OK\n");
	}

	close(fd);
	pass();
	return 0;

failed:
	close(fd);
	return 1;
}
