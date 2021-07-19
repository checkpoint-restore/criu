#include <fcntl.h>
#include <limits.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc = "Check c/r of non-breaking leases";
const char *test_author = "Pavel Begunkov <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
char filename_rd[PATH_MAX];
char filename_wr[PATH_MAX];

static void close_files(int fd1, int fd2)
{
	if (fd1 >= 0)
		close(fd1);
	if (fd2 >= 0)
		close(fd2);

	unlink(filename_rd);
	unlink(filename_wr);
}

static int open_files(int *fd_rd, int *fd_wr)
{
	*fd_rd = open(filename_rd, O_RDONLY | O_CREAT, 0666);
	*fd_wr = open(filename_wr, O_WRONLY | O_CREAT, 0666);

	if (*fd_rd < 0 || *fd_wr < 0) {
		close_files(*fd_rd, *fd_wr);
		return -1;
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
	int fd_rd = -1, fd_wr = -1;

	test_init(argc, argv);

	snprintf(filename_rd, sizeof(filename_rd), "%s.0", filename);
	snprintf(filename_wr, sizeof(filename_wr), "%s.1", filename);

	if (open_files(&fd_rd, &fd_wr)) {
		pr_err("Can't open files\n");
		return -1;
	}
	if (fcntl(fd_rd, F_SETLEASE, F_RDLCK) < 0 || fcntl(fd_wr, F_SETLEASE, F_WRLCK) < 0) {
		pr_perror("Can't set leases");
		close_files(fd_rd, fd_wr);
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (check_lease_type(fd_rd, F_RDLCK))
		fail("Read lease check failed");
	else if (check_lease_type(fd_wr, F_WRLCK))
		fail("Write lease check failed");
	else
		pass();

	close_files(fd_rd, fd_wr);
	return 0;
}
