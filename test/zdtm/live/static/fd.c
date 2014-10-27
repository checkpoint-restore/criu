#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Check that criu closes up all its descriptors";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

int main(int argc, char **argv)
{
	struct dirent *de;
	char pfd[PATH_MAX];
	mutex_t *lock;
	int status;
	pid_t pid;
	DIR *d;

	test_init(argc, argv);

	lock = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (lock == MAP_FAILED)
		return 1;

	mutex_init(lock);
	mutex_lock(lock);

	pid = fork();
	if (pid < 0) {
		err("fork()");
		return 1;
	}

	if (pid == 0) {

		d = opendir("/proc/self/fd");
		if (d == NULL)
			return 1;

		while ((de = readdir(d))) {
			int fd;

			if (de->d_name[0] == '.')
				continue;

			fd = atoi(de->d_name);
			if (dirfd(d) == fd)
				continue;
			close(fd);
		}

		closedir(d);
		mutex_unlock(lock);

		test_waitsig();

		return 0;
	}

	mutex_lock(lock);

	test_daemon();
	test_waitsig();

	snprintf(pfd, sizeof(pfd), "/proc/%d/fd", pid);
	d = opendir(pfd);
	if (d == NULL)
		return 2;

	while ((de = readdir(d))) {
		int ret;

		if (de->d_name[0] == '.')
			continue;

		ret = readlinkat(dirfd(d), de->d_name, pfd, sizeof(pfd) - 1);
		if (ret < 0) {
			err("readlink");
			ret = 0;
		}
		pfd[ret] = '\0';
		fail("Unexpected fd: %s -> %s\n", de->d_name, pfd);
		return 1;
	}

	closedir(d);
	kill(pid, SIGTERM);

	if (waitpid(pid, &status, 0) != pid) {
		err("waitpid()");
		return 1;
	}

	if (status != 0) {
		fail("%d:%d:%d:%d", WIFEXITED(status), WEXITSTATUS(status),
					WIFSIGNALED(status), WTERMSIG(status));
		return 1;
	}

	pass();

	return 0;
}
