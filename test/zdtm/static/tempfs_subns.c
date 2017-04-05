#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <signal.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check tmpfs in a non-root mntns";
const char *test_author	= "Andrew Vagin <avagin@virtuozzo.com";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int fds[2], i;
	pid_t pid;
	int fd, status;

	test_init(argc, argv);

	if (pipe(fds)) {
		pr_perror("pipe");
		return 1;
	}

	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		pr_perror("mount");
	}
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}
	if (pid == 0) {
		void *addr;

		pid = fork();
		if (pid == 0) {
			if (write(fds[1], &fd, sizeof(fd)) != sizeof(fd)) {
				pr_perror("write");
				return 1;
			}
			if (unshare(CLONE_NEWNS)) {
				pr_perror("unshare");
				return 1;
			}
			prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
			while (1)
				sleep(1);
			return 1;
		}
		pid = fork();
		if (pid == 0) {
			if (write(fds[1], &fd, sizeof(fd)) != sizeof(fd)) {
				pr_perror("write");
				return 1;
			}
			prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
			while (1)
				sleep(1);
			return 1;
		}
		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare");
			return 1;
		}
		mkdir(dirname, 0755);
		if (mount("zdtm", dirname, "tmpfs", 0, NULL)) {
			pr_perror("mount");
			return 1;
		}

		chdir(dirname);
		fd = open("test", O_CREAT | O_RDWR | O_APPEND, 0666);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}
		ftruncate(fd, PAGE_SIZE);
		addr = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
		if (addr == MAP_FAILED) {
			pr_perror("mmap");
			return 1;
		}

		if (write(fds[1], &fd, sizeof(fd)) != sizeof(fd)) {
			pr_perror("write");
			return 1;
		}

		test_waitsig();
		if (close(fd)) {
			pr_perror("close");
			return 1;
		}

		fd = open("test", O_RDONLY | O_APPEND);
		if (fd < 0) {
			pr_perror("open");
			return 1;
		}
		close(fd);
		return 0;
	}
	close(fds[1]);

	for (i = 0; i < 3; i++) {
		if (read(fds[0], &fd, sizeof(fd)) != sizeof(fd)) {
			pr_perror("read");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	kill(pid, SIGTERM);
	status = -1;
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		return 1;
	}
	if (status) {
		pr_err("Returned non-zero code: 0x%x\n", status);
		return 1;
	}
	pass();
	return 0;
}
