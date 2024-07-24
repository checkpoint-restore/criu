#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of pidfds that point to dead processes\n";
const char *test_author = "Bhavik Sachdev <b.sachdev1904@gmail.com>";

#ifndef PID_FS_MAGIC
#define PID_FS_MAGIC 0x50494446
#endif

/*
 * main
 *	`- child
 *		`- grandchild
 *
 * main opens a pidfd for both child and grandchild.
 * Before C/R we kill both child and grandchild.
 * We end up with two unique dead pidfds.
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

static int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

static int open_pidfd_pair(int pidfd[2], int pid)
{
	pidfd[0] = pidfd_open(pid, 0);
	if (pidfd[0] < 0) {
		pr_perror("pidfd_open() failed");
		return 1;
	}

	pidfd[1] = pidfd_open(pid, 0);
	if (pidfd[1] < 0) {
		close(pidfd[0]);
		pr_perror("pidfd_open() failed");
		return 1;
	}
	return 0;
}

static int compare_pidfds(int pidfd[2])
{
	/*
	* After linux 6.9 we can compare inode numbers
	* to determine if two pidfds point to the same process.
	* While the inode number may change before and after C/R
	* pidfds pointing to the same pid should have the same inode number.
	*/
	struct statx stats[2];
	statx(pidfd[0], "", AT_EMPTY_PATH, STATX_ALL, &stats[0]);
	statx(pidfd[1], "", AT_EMPTY_PATH, STATX_ALL, &stats[1]);
	if (stats[0].stx_ino != stats[1].stx_ino)
		return 1;
	return 0;
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

int main(int argc, char* argv[])
{
	#define READ 0
	#define WRITE 1

	int child, ret, gchild, p[2], status;
	int cpidfd[2], gpidfd[2];
	struct statx stats[2];

	test_init(argc, argv);

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
		int gchild = test_fork();
		close(p[READ]);
		if (gchild < 0) {
			pr_perror("fork");
			return 1;
		} else if (gchild == 0) {
			close(p[WRITE]);
			while(1)
				sleep(1000);
		} else {
			if (write(p[WRITE], &gchild, sizeof(int)) != sizeof(int)) {
				pr_perror("write");
				return 1;
			}
			close(p[WRITE]);
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

			return 0;
		}
	}

	ret = open_pidfd_pair(cpidfd, child);
	if (ret)
		return 1;

	close(p[WRITE]);
	if (read(p[READ], &gchild, sizeof(int)) != sizeof(int)) {
		pr_perror("write");
		return 1;
	}
	close(p[READ]);

	ret = open_pidfd_pair(gpidfd, gchild);
	if (ret)
		return 1;

	/*
	* We kill grandchild and child processes only after opening pidfds.
	*/
	if (pidfd_send_signal(gpidfd[0], SIGKILL, NULL, 0)) {
		pr_perror("pidfd_send_signal");
		goto fail_close;
	}

	if (waitpid(child, &status, 0) != child) {
		pr_perror("waitpid");
		goto fail_close;
	}

	if (!WIFEXITED(status)) {
		fail("Expected child to exit normally");
		goto fail_close;
	}

	if (WEXITSTATUS(status) != 0) {
		fail("Expected child to exit with 0");
		goto fail_close;
	}
	usleep(1000);

	if (kill(gchild, 0) != -1 && errno != ESRCH) {
		fail("Expected grand child to not exist");
		goto fail_close;
	}

	if (kill(child, 0) != -1 && errno != ESRCH) {
		fail("Expected child to not exist");
		goto fail_close;
	}

	test_daemon();
	test_waitsig();

	ret = compare_pidfds(cpidfd);
	if (ret) {
		fail("inodes not same for same pid");
		goto fail_close;
	}

	ret = compare_pidfds(gpidfd);
	if (ret) {
		fail("inodes not same for same pid");
		goto fail_close;
	}

	statx(cpidfd[0], "", AT_EMPTY_PATH, STATX_ALL, &stats[0]);
	statx(gpidfd[0], "", AT_EMPTY_PATH, STATX_ALL, &stats[1]);
	if (stats[0].stx_ino == stats[1].stx_ino) {
		fail("pidfds pointing to diff pids should have diff inodes");
		goto fail_close;
	}

	pass();
	close(cpidfd[0]);
	close(cpidfd[1]);
	close(gpidfd[0]);
	close(gpidfd[1]);
	return 0;

fail_close:
	close(cpidfd[0]);
	close(cpidfd[1]);
	close(gpidfd[0]);
	close(gpidfd[1]);
	return 1;
}
