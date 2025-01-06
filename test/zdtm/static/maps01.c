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

#define MEM_SIZE    (1LU << 30)
#define MEM_OFFSET  (1LU << 29)
#define MEM_OFFSET2 (MEM_SIZE - PAGE_SIZE)
#define MEM_OFFSET3 (20LU * PAGE_SIZE)

const char *test_doc = "Test shared memory";
const char *test_author = "Andrew Vagin <avagin@openvz.org";

int main(int argc, char **argv)
{
	void *m, *m2, *p, *p2;
	char path[PATH_MAX];
	uint32_t crc;
	pid_t pid = -1;
	int status, fd;
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	m = mmap(NULL, MEM_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (m == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb shared anonymous R/W memory", MEM_SIZE >> 20);
		goto err;
	}

	p = mmap(NULL, MEM_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		pr_perror("Failed to mmap %ld Mb shared anonymous R/W memory", MEM_SIZE >> 20);
		goto err;
	}

	p2 = mmap(NULL, MEM_OFFSET, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p2 == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb anonymous memory", MEM_OFFSET >> 20);
		goto err;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_err("Fork failed with %d\n", pid);
		goto err;
	} else if (pid == 0) {
		void *p3;

		p3 = mmap(NULL, MEM_OFFSET3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p3 == MAP_FAILED) {
			pr_perror("Failed to mmap %lu Mb anonymous R/W memory", MEM_OFFSET3 >> 20);
			goto err;
		}

		crc = ~0;
		datagen(m + MEM_OFFSET, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(m + MEM_OFFSET2, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(p + MEM_OFFSET + MEM_OFFSET3, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(p + MEM_OFFSET + 2 * MEM_OFFSET3, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(p + MEM_OFFSET3, PAGE_SIZE, &crc);
		crc = ~0;
		datagen(p3, PAGE_SIZE, &crc);

		task_waiter_complete(&t, 1);

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
		crc = ~0;
		status = datachk(p + MEM_OFFSET + 2 * MEM_OFFSET3, PAGE_SIZE, &crc);
		if (status)
			return 1;
		crc = ~0;
		status = datachk(p + MEM_OFFSET3, PAGE_SIZE, &crc);
		if (status)
			return 1;
		crc = ~0;
		status = datachk(p3, PAGE_SIZE, &crc);
		if (status)
			return 1;
		return 0;
	}
	task_waiter_wait4(&t, 1);

	munmap(p, MEM_OFFSET);
	p2 = mremap(p + MEM_OFFSET, MEM_OFFSET, MEM_OFFSET, MREMAP_FIXED | MREMAP_MAYMOVE, p2);
	if (p2 == MAP_FAILED)
		goto err;

	snprintf(path, PATH_MAX, "/proc/self/map_files/%lx-%lx", (unsigned long)m, (unsigned long)m + MEM_SIZE);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		pr_perror("Can't open file %s", path);
		goto err;
	}

	m2 = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, fd, MEM_OFFSET3);
	if (m2 == MAP_FAILED) {
		pr_perror("Can't map file %s", path);
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

	crc = ~0;
	if (datachk(p2 + MEM_OFFSET3, PAGE_SIZE, &crc))
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
