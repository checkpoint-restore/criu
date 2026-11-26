#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>

#include "zdtmtst.h"
#include "lock.h"

#ifdef ZDTM_UNLINK_MMAP_TASKS
const char *test_doc = "Test mmapped and unlinked files, mapped by several "
		       "tasks and replaced by a new file with the same name";
#else
const char *test_doc = "Test mmapped and unlinked files";
#endif

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void touch_file_page(int fd, unsigned long off, char c)
{
	if (lseek(fd, off, SEEK_SET) != off) {
		pr_perror("Lseek fail");
		exit(1);
	}

	if (write(fd, &c, 1) != 1) {
		pr_perror("Write fail");
		exit(1);
	}
}

static char *mem_a, *mem_b;

static void map_file(int fd)
{
	/* map with different prots to create 2 regions */
	mem_a = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	mem_b = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, PAGE_SIZE);
	if (mem_a == MAP_FAILED || mem_b == MAP_FAILED) {
		pr_perror("can't map file");
		exit(1);
	}
}

static const char *check_maps(void)
{
	if (mem_a[0] != 'a')
		return "1st region fail";
	if (mem_b[0] != 'b' || mem_b[PAGE_SIZE - 1] != 'c')
		return "2nd region fail";
	return NULL;
}

#ifdef ZDTM_UNLINK_MMAP_TASKS
#define NR_TASKS 64

static futex_t *ready, *restored;
static pid_t pids[NR_TASKS];

static void kill_tasks(void)
{
	int i;

	for (i = 0; i < NR_TASKS && pids[i] > 0; i++) {
		kill(pids[i], SIGKILL);
		waitpid(pids[i], NULL, 0);
	}
}

static int task(int fd)
{
	const char *err;

	map_file(fd);
	close(fd);

	futex_inc_and_wake(ready);
	futex_wait_until(restored, 1);

	err = check_maps();
	if (err) {
		pr_err("%s\n", err);
		return 1;
	}
	return 0;
}

/*
 * Only the child tasks map the file: if the parent mapped it too, on
 * restore the children would inherit the vma from it (vma_inherited()
 * in criu) instead of opening the deleted file themselves via
 * open_filemap()->open_path(), and the concurrent opens would not be
 * tested.
 */
static void start_tasks(int fd)
{
	int i;

	ready = mmap(NULL, 2 * sizeof(futex_t), PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ready == MAP_FAILED) {
		pr_perror("can't map shared memory");
		exit(1);
	}
	restored = ready + 1;
	futex_init(ready);
	futex_init(restored);

	for (i = 0; i < NR_TASKS; i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			pr_perror("can't fork");
			kill_tasks();
			exit(1);
		}
		if (pids[i] == 0)
			exit(task(fd));
	}

	futex_wait_until(ready, NR_TASKS);
}

/*
 * Take the name of the unlinked file, so that on restore it can't be
 * linked back and has to go through a fake .cr_link name.
 */
static void replace_file(void)
{
	int fd;

	fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		pr_perror("can't create new file");
		kill_tasks();
		exit(1);
	}
	touch_file_page(fd, 0, 'z');
	close(fd);
}

static const char *check_tasks(void)
{
	const char *err = NULL;
	char link_name[PATH_MAX], c;
	int i, status, fd;

	futex_set_and_wake(restored, 1);

	for (i = 0; i < NR_TASKS; i++) {
		if (waitpid(pids[i], &status, 0) != pids[i] ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			err = "task fail";
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0 || read(fd, &c, 1) != 1 || c != 'z')
		err = "new file fail";
	if (fd >= 0)
		close(fd);

	snprintf(link_name, sizeof(link_name), "%s.cr_link", filename);
	if (access(link_name, F_OK) == 0)
		err = "leftover .cr_link file";

	unlink(filename);
	return err;
}
#endif

int main(int argc, char **argv)
{
	const char *err;
	int fd;

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open file");
		exit(1);
	}

	touch_file_page(fd, 0, 'a');
	touch_file_page(fd, PAGE_SIZE, 'b');
	touch_file_page(fd, 2 * PAGE_SIZE - 1, 'c'); /* for aligned file */

#ifdef ZDTM_UNLINK_MMAP_TASKS
	start_tasks(fd);
#else
	map_file(fd);
#endif

	if (unlink(filename) < 0) {
		pr_perror("can't unlink file");
		exit(1);
	}

	close(fd);

#ifdef ZDTM_UNLINK_MMAP_TASKS
	replace_file();
#endif

	test_daemon();
	test_waitsig();

#ifdef ZDTM_UNLINK_MMAP_TASKS
	err = check_tasks();
#else
	err = check_maps();
#endif
	if (err)
		fail("%s", err);
	else
		pass();

	return 0;
}
