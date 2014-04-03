#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include "zdtmtst.h"

const char *test_doc	= "Test mappings of same file with different prot";
const char *test_author	= "Jamie Liu <jamieliu@google.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define die(fmt, arg...) do { err(fmt, ## arg); return 1; } while (0)

int main(int argc, char ** argv)
{
	void *ro_map, *rw_map;
	int fd;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		die("open failed");
	if (ftruncate(fd, 2 * PAGE_SIZE))
		die("ftruncate failed");

	ro_map = mmap(NULL, 2 * PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (ro_map == MAP_FAILED)
		die("mmap failed");
	rw_map = ro_map + PAGE_SIZE;
	if (mprotect(rw_map, PAGE_SIZE, PROT_READ | PROT_WRITE))
		die("mprotect failed");

	close(fd);

	test_daemon();
	test_waitsig();

	/* Check that rw_map is still writeable */
	*(volatile char *)rw_map = 1;

	if (mprotect(ro_map, PAGE_SIZE, PROT_READ | PROT_WRITE)) {
		fail("mprotect after restore failed");
		return 1;
	}

	pass();
	return 0;
}
