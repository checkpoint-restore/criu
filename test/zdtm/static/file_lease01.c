#include <fcntl.h>
#include <stdio.h>

#include "zdtmtst.h"

#define FD_COUNT      3
#define FD_LEASED1    0
#define FD_LEASED2    2
#define FD_LEASE_FREE 1

const char *test_doc = "Check that extra leases are not set after c/r";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

static void close_files(int fds[FD_COUNT])
{
	int i;

	for (i = 0; i < FD_COUNT; ++i)
		if (fds[i] >= 0)
			close(fds[i]);
	unlink(filename);
}

static int open_files(int fds[FD_COUNT])
{
	int i;

	for (i = 0; i < FD_COUNT; ++i) {
		fds[i] = open(filename, O_RDONLY | O_CREAT, 0666);
		if (fds[i] < 0) {
			close_files(fds);
			return -1;
		}
	}
	return 0;
}

static int check_lease_type(int fd, int expected_type)
{
	int lease_type = fcntl(fd, F_GETLEASE);

	if (lease_type != expected_type) {
		if (lease_type < 0)
			pr_perror("Can't acquire lease type");
		else
			pr_err("Mismatched lease type: %i\n", lease_type);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int fds[FD_COUNT];

	test_init(argc, argv);

	if (open_files(fds)) {
		pr_err("Can't open files\n");
		return -1;
	}

	if (fcntl(fds[FD_LEASED1], F_SETLEASE, F_RDLCK) < 0 || fcntl(fds[FD_LEASED2], F_SETLEASE, F_RDLCK) < 0) {
		pr_err("Can't set leases\n");
		close_files(fds);
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (check_lease_type(fds[FD_LEASE_FREE], F_UNLCK))
		fail("Unexpected lease was found (%i)", fds[FD_LEASE_FREE]);
	else if (check_lease_type(fds[FD_LEASED1], F_RDLCK))
		fail("Lease isn't set (%i)", fds[FD_LEASED1]);
	else if (check_lease_type(fds[FD_LEASED2], F_RDLCK))
		fail("Lease isn't set (%i)", fds[FD_LEASED2]);
	else
		pass();

	close_files(fds);
	return 0;
}
