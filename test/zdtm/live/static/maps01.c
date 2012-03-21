#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include "zdtmtst.h"

#define PAGE_SIZE 4096
#define MEM_SIZE (1L << 30)
#define MEM_OFFSET (1L << 29)
#define MEM_OFFSET2 (MEM_SIZE - PAGE_SIZE)
#define MEM_OFFSET3 (20 * PAGE_SIZE)

const char *test_doc	= "Test shared memory";
const char *test_author	= "Andrew Vagin <avagin@openvz.org";

int main(int argc, char ** argv)
{
	void *m, *m2;
	char path[PATH_MAX];
	uint32_t crc;
	pid_t pid = -1;
	int status, fd;

	test_init(argc, argv);

	m = mmap(NULL, MEM_SIZE, PROT_WRITE | PROT_READ,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (m == MAP_FAILED)
		goto err;

	pid = test_fork();
	if (pid < 0) {
		goto err;
	} else if (pid == 0) {
		crc = ~0;
		datagen(m + MEM_OFFSET, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(m + MEM_OFFSET2, PAGE_SIZE, &crc);

		test_waitsig();

		crc = ~0;
		status = datachk(m + MEM_OFFSET, PAGE_SIZE, &crc);
		if (status)
			return 1;
		crc = ~0;
		status = datachk(m + MEM_OFFSET2, PAGE_SIZE, &crc);
		if (status)
			return 1;
		crc = ~0;
		status = datachk(m + PAGE_SIZE, PAGE_SIZE, &crc);
		if (status)
			return 1;
		return 0;
	}

	snprintf(path, PATH_MAX, "/proc/self/map_files/%lx-%lx",
						(unsigned long) m,
						(unsigned long) m + MEM_SIZE);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		err("Can't open file %s: %m", path);
		goto err;
	}

	m2 = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, fd, MEM_OFFSET3);
	if (m2 == MAP_FAILED) {
		err("Can't map file %s", path);
		goto err;
	}
	close(fd);

	munmap(m, PAGE_SIZE);
	munmap(m + PAGE_SIZE * 10, PAGE_SIZE);
	munmap(m + MEM_OFFSET2, PAGE_SIZE);

	crc = ~0;
	datagen(m + PAGE_SIZE, PAGE_SIZE, &crc);

	crc = ~0;
	datagen(m2, PAGE_SIZE, &crc);

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	wait(&status);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			goto err;
	} else
		goto err;

	crc = ~0;
	if (datachk(m + MEM_OFFSET, PAGE_SIZE, &crc))
		goto err;

	crc = ~0;
	if (datachk(m2, PAGE_SIZE, &crc))
		goto err;

	pass();

	return 0;
err:
	if (waitpid(-1, NULL, WNOHANG) == 0) {
		kill(pid, SIGTERM);
		wait(NULL);
	}
	return 1;
}
