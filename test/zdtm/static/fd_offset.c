#include <fcntl.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check that criu properly restores offsets on ELF files";
const char *test_author = "Michal Clapinski <mclapinski@google.com>";

void check_offset(int fd)
{
	int offset = lseek(fd, 0, SEEK_CUR);
	if (offset < 0) {
		fail("lseek");
		exit(1);
	}
	if (offset != 0) {
		fail("wrong offset; expected: 0, got: %d", offset);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int fd;

	test_init(argc, argv);

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0) {
		fail("open");
		exit(1);
	}
	check_offset(fd);

	test_daemon();
	test_waitsig();

	check_offset(fd);

	pass();
	return 0;
}
