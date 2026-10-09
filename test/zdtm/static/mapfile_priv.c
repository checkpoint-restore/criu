#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check mapped file survives C/R when path is only visible inside a mount namespace";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

enum {
	EXIT_SETUP = 1,
	EXIT_MAGIC_MISMATCH = 2,
	EXIT_BACKING_MISMATCH = 3,
};

int main(int argc, char **argv)
{
	int sync_pipe[2], pid, status;

	test_init(argc, argv);

	if (pipe(sync_pipe)) {
		pr_perror("pipe");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		char path[256];
		uint32_t file_value;
		uint32_t *addr;
		int fd;

		close(sync_pipe[0]);

		if (unshare(CLONE_NEWNS)) {
			pr_perror("unshare CLONE_NEWNS");
			exit(EXIT_SETUP);
		}

		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			pr_perror("mount --make-rprivate /");
			exit(EXIT_SETUP);
		}

		if (mount("zdtm_mapfile_priv", "/tmp", "tmpfs", 0, NULL)) {
			pr_perror("mount tmpfs on /tmp");
			exit(EXIT_SETUP);
		}

		snprintf(path, sizeof(path), "/tmp/zdtm_mapfile_%d", getpid());
		fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0) {
			pr_perror("open %s", path);
			exit(EXIT_SETUP);
		}

		if (ftruncate(fd, PAGE_SIZE)) {
			pr_perror("ftruncate");
			close(fd);
			exit(EXIT_SETUP);
		}

		addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		if (addr == MAP_FAILED) {
			pr_perror("mmap file");
			exit(EXIT_SETUP);
		}

		addr[0] = 0xDEADBEEF;

		/* Tell parent we're set up */
		if (write(sync_pipe[1], &(char){1}, 1) != 1) {
			pr_perror("sync write");
			exit(EXIT_SETUP);
		}
		close(sync_pipe[1]);

		test_waitsig();

		if (addr[0] != 0xDEADBEEF) {
			test_msg("FAIL: mapped file content lost after C/R (got 0x%x, expected 0x%x)\n",
				 addr[0], 0xDEADBEEF);
			exit(EXIT_MAGIC_MISMATCH);
		}
		addr[1] = 0xC0FFEE;

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			pr_perror("open %s after C/R", path);
			exit(EXIT_BACKING_MISMATCH);
		}
		if (pread(fd, &file_value, sizeof(file_value), sizeof(addr[0])) != sizeof(file_value)) {
			pr_perror("pread mapped file after C/R");
			close(fd);
			exit(EXIT_BACKING_MISMATCH);
		}
		close(fd);
		if (file_value != 0xC0FFEE) {
			test_msg("FAIL: mapped file is not backed by restored file (got 0x%x, expected 0x%x)\n",
				 file_value, 0xC0FFEE);
			exit(EXIT_BACKING_MISMATCH);
		}

		exit(0);
	}

	close(sync_pipe[1]);

	/* Wait for child to finish setup before telling zdtm we're ready */
	if (read(sync_pipe[0], &(char){0}, 1) != 1) {
		pr_perror("sync read");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return 1;
	}
	close(sync_pipe[0]);

	test_daemon();
	test_waitsig();

	if (kill(pid, SIGTERM)) {
		pr_perror("kill child");
		return 1;
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		return 1;
	}

	if (WIFSIGNALED(status)) {
		fail("child killed by signal %d", WTERMSIG(status));
		return 1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SETUP) {
		fail("child setup failed");
		return 1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_MAGIC_MISMATCH) {
		fail("child reported data corruption after C/R");
		return 1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_BACKING_MISMATCH) {
		fail("child reported restored mapping is not backed by the file");
		return 1;
	}
	if (status) {
		fail("child exited with unknown status 0x%x", status);
		return 1;
	}

	pass();
	return 0;
}
