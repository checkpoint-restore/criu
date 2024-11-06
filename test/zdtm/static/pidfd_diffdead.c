#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of processes that point to a common dead pidfd\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

/*
 * main
 *	`- child
 *		`- grandchild
 *
 * main and child open a pidfd for grandchild.
 * Before C/R we kill grandchild.
 * We end up with two pidfds in two diff processes that point to the same dead process.
 */

static long get_fs_type(int lfd)
{
	struct statfs fst;

	if (fstatfs(lfd, &fst)) {
		return -1;
	}
	return fst.f_type;
}

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static int check_for_pidfs(void)
{
	long type;
	int pidfd = pidfd_open(getpid(), 0);
	if (pidfd < 0) {
		pr_perror("pidfd open() failed");
		return -1;
	}
	type = get_fs_type(pidfd);
	close(pidfd);
	return type == PID_FS_MAGIC;
}

int main(int argc, char *argv[])
{
#define READ  0
#define WRITE 1

	int child, ret, gchild, status;
	struct statx stat;
	task_waiter_t t;
	unsigned long long ino;

	/*
	 * We use the inop pipe to send the inode number of the
	 * pidfd opened in the child to the main process for
	 * comparison.
	 */
	int p[2];
	int pidfd;

	test_init(argc, argv);
	task_waiter_init(&t);

	ret = check_for_pidfs();
	if (ret < 0)
		return 1;

	if (ret == 0) {
		test_daemon();
		test_waitsig();
		skip("Test requires pidfs. skipping...");
		pass();
		return 0;
	}

	if (pipe(p)) {
		pr_perror("pipe");
		return 1;
	}

	child = test_fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	} else if (child == 0) {
		int gchild;
		gchild = test_fork();
		if (gchild < 0) {
			pr_perror("fork");
			return 1;
		} else if (gchild == 0) {
			close(p[READ]);
			close(p[WRITE]);
			while (1)
				sleep(1000);
		} else {
			if (write(p[WRITE], &gchild, sizeof(int)) != sizeof(int)) {
				pr_perror("write");
				return 1;
			}

			pidfd = pidfd_open(gchild, 0);
			if (pidfd < 0) {
				pr_perror("pidfd_open");
				return 1;
			}

			if (waitpid(gchild, &status, 0) != gchild) {
				pr_perror("waitpid");
				return 1;
			}

			if (!WIFSIGNALED(status)) {
				fail("Expected grandchild to be terminated by a signal");
				return 1;
			}

			if (WTERMSIG(status) != SIGKILL) {
				fail("Expected grandchild to be terminated by SIGKILL");
				return 1;
			}
			task_waiter_complete(&t, 1);

			test_waitsig();

			if (statx(pidfd, "", AT_EMPTY_PATH, STATX_ALL, &stat) < 0) {
				pr_perror("statx");
				return 1;
			}

			close(p[WRITE]);
			if (read(p[READ], &ino, sizeof(ino)) != sizeof(ino)) {
				pr_perror("read");
				return 1;
			}
			close(p[READ]);
			close(pidfd);

			/* ino number should be same because both pidfds were for the same process */
			if (ino != stat.stx_ino) {
				exit(1);
			}
			exit(0);
		}
	}

	if (read(p[READ], &gchild, sizeof(int)) != sizeof(int)) {
		pr_perror("write");
		return 1;
	}

	pidfd = pidfd_open(gchild, 0);
	if (pidfd < 0) {
		pr_perror("pidfd_open");
		return 1;
	}

	/*
	* We kill grandchild process only after opening pidfd.
	*/
	if (pidfd_send_signal(pidfd, SIGKILL, NULL, 0)) {
		pr_perror("pidfd_send_signal");
		return 1;
	}

	/* Wait for child to waitpid on gchild */
	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	close(p[READ]);
	if (statx(pidfd, "", AT_EMPTY_PATH, STATX_ALL, &stat) < 0) {
		pr_perror("statx");
		goto err;
	}

	/* Send inode number of pidfd to child for comparison */
	if (write(p[WRITE], &stat.stx_ino, sizeof(stat.stx_ino)) != sizeof(stat.stx_ino)) {
		pr_perror("write");
		goto err;
	}
	close(p[WRITE]);

	if (kill(child, SIGTERM)) {
		pr_perror("kill");
		goto err;
	}

	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid");
		goto err;
	}

	if (!WIFEXITED(status)) {
		fail("Expected child to terminate normally");
		goto err;
	}

	if (WEXITSTATUS(status) != 0) {
		fail("Child failed");
		goto err;
	}

	pass();
	close(pidfd);
	return 0;
err:
	close(pidfd);
	return 1;
}
