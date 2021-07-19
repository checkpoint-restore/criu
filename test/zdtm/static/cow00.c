#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/user.h>

#include "zdtmtst.h"

const char *test_doc = "Check that cow memory are restored";
const char *test_author = "Andrey Vagin <avagin@parallels.com";

static int is_cow(void *addr, pid_t p1, pid_t p2)
{
	char buf[PATH_MAX];
	unsigned long pfn = (unsigned long)addr / PAGE_SIZE;
	uint64_t map1, map2;
	int fd1, fd2, ret, i;

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", p1);
	fd1 = open(buf, O_RDONLY);
	if (fd1 < 0) {
		pr_perror("Unable to open file %s", buf);
		return -1;
	}

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", p2);
	fd2 = open(buf, O_RDONLY);
	if (fd1 < 0) {
		pr_perror("Unable to open file %s", buf);
		return -1;
	}

	/*
	 * A page can be swapped or unswapped,
	 * so we should do several iterations.
	 */
	for (i = 0; i < 10; i++) {
		lseek(fd1, pfn * sizeof(map1), SEEK_SET);
		lseek(fd2, pfn * sizeof(map2), SEEK_SET);

		ret = read(fd1, &map1, sizeof(map1));
		if (ret != sizeof(map1)) {
			pr_perror("Unable to read data");
			return -1;
		}
		ret = read(fd2, &map2, sizeof(map2));
		if (ret != sizeof(map2)) {
			pr_perror("Unable to read data");
			return -1;
		}

		if (map1 == map2)
			break;
	}

	close(fd1);
	close(fd2);

	return map1 == map2;
}

int main(int argc, char **argv)
{
	void *addr;
	pid_t pid;
	int ret = 1;

	test_init(argc, argv);

	addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't allocate memory");
		return 1;
	}

	memset(addr, 1, PAGE_SIZE);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Unable to fork a new process");
		return 1;
	} else if (pid == 0) {
		test_waitsig();
		return 0;
	}

	if (is_cow(addr, pid, getpid()) == 1)
		test_msg("OK\n");
	else {
		pr_perror("A page is not shared");
		goto out;
	}

	test_daemon();

	test_waitsig();

	if (is_cow(addr, pid, getpid()) == 1)
		pass();
	else
		fail("A page is not shared");

	ret = 0;
out:
	kill(pid, SIGTERM);
	wait(NULL);

	return ret;
}
