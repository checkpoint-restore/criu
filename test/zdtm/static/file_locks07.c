#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>

#include "ofd_file_locks.h"
#include "zdtmtst.h"

const char *test_doc    = "Check that 'overlapping' OFD read locks work";
const char *test_author = "Begunkov Pavel <asml.silence@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);


#define FILE_NUM 4
static int fds[FILE_NUM];
static struct flock lcks[FILE_NUM];
static short types[] = {F_RDLCK, F_RDLCK, F_RDLCK, F_RDLCK};
static off_t starts[] = {0, 10, 0, 70};
static off_t lens[]  = {20, 30, 100, 200};

void fill_lock(struct flock *lock, off_t start, off_t len, short int type)
{
	lock->l_start = start;
	lock->l_len = len;
	lock->l_type = type;
	lock->l_whence = SEEK_SET;
	lock->l_pid = 0;
}

int init_file_locks(void)
{
	size_t i;

	for (i = 0; i < FILE_NUM; ++i)
		fill_lock(&lcks[i], starts[i], lens[i], types[i]);

	for (i = 0; i < FILE_NUM; ++i) {
		fds[i] = open(filename, O_RDWR | O_CREAT, 0666);

		if (fds[i] < 0) {
			pr_perror("Can't open file");
			return -1;
		}
	}

	for (i = 0; i < FILE_NUM; ++i)
		if (fcntl(fds[i], F_OFD_SETLKW, &lcks[i]) < 0) {
			pr_perror("Can't set ofd lock");
			return -1;
		}

	return 0;
}

void cleanup(void)
{
	size_t i;

	for (i = 0; i < FILE_NUM; ++i)
		if (close(fds[i]))
			pr_perror("Can't close fd\n");

	if (unlink(filename))
		pr_perror("Can't unlink file failed\n");
}

int check_file_locks_restored(void)
{
	size_t i;
	int pid = getpid();

	for (i = 0; i < FILE_NUM; ++i) {
		if (check_file_lock_restored(pid, fds[i], &lcks[i]))
			return -1;
		if (check_lock_exists(filename, &lcks[i]) < 0)
			return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);
	if (init_file_locks())
		return -1;

	test_daemon();
	test_waitsig();

	if (check_file_locks_restored())
		fail("OFD file locks check failed\n");
	else
		pass();

	cleanup();
	return 0;
}
