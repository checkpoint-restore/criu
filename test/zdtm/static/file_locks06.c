#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>

#include "ofd_file_locks.h"
#include "zdtmtst.h"

const char *test_doc    = "Check that OFD lock for the whole file is restored";
const char *test_author = "Begunkov Pavel <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);


int init_lock(int *fd, struct flock *lck)
{
	*fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (*fd < 0) {
		pr_perror("Can't open file");
		return -1;
	}

	lck->l_type = F_WRLCK;
	lck->l_whence = SEEK_SET;
	lck->l_start = 0;
	lck->l_len = 0;
	lck->l_pid = 0;

	if (fcntl(*fd, F_OFD_SETLK, lck) < 0) {
		pr_perror("Can't set ofd lock");
		return -1;
	}
	return 0;
}

void cleanup(int *fd)
{
	if (close(*fd))
		pr_perror("Can't close fd\n");

	if (unlink(filename))
		pr_perror("Can't unlink file\n");
}

int main(int argc, char **argv)
{
	int fd;
	struct flock lck;

	test_init(argc, argv);
	if (init_lock(&fd, &lck))
		return 1;

	test_daemon();
	test_waitsig();

	if (check_file_lock_restored(getpid(), fd, &lck) ||
		check_lock_exists(filename, &lck) < 0)
		fail("OFD file locks check failed\n");
	else
		pass();

	cleanup(&fd);
	return 0;
}
