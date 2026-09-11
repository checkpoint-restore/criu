#include "criu.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lib.h"

#define CRIU_FAULT_SECCOMP_NO_IMAGE_FILTERS "140"
#define RESTORE_NO_SECCOMP 44

/*
 * Dumped filter: deny ptrace. On restore we supply a different BPF program
 * that denies getpid, so a passing test proves the RPC-supplied BPF was used.
 */
static struct sock_filter deny_ptrace_filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_ptrace, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
};

static struct sock_filter deny_getpid_filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getpid, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
};

static int install_seccomp(void)
{
	struct sock_fprog prog = {
		.len = sizeof(deny_ptrace_filter) / sizeof(deny_ptrace_filter[0]),
		.filter = deny_ptrace_filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("PR_SET_NO_NEW_PRIVS");
		return -1;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("PR_SET_SECCOMP");
		return -1;
	}

	return 0;
}

static void trigger_getpid(int signo)
{
	(void)signo;
	syscall(__NR_getpid);
	_exit(RESTORE_NO_SECCOMP);
}

static void init_criu(char *criu_bin, int dir_fd, const char *log_file)
{
	criu_init_opts();
	criu_set_service_binary(criu_bin);
	criu_set_images_dir_fd(dir_fd);
	criu_set_log_level(CRIU_LOG_DEBUG);
	criu_set_log_file(log_file);
}

int main(int argc, char **argv)
{
	int dir_fd, ready[2], ret, status;
	pid_t pid;
	char c;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s CRIU-BIN IMAGE-DIR\n", argv[0]);
		return 1;
	}

	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd < 0) {
		perror("Can't open images dir");
		return 1;
	}

	if (pipe(ready)) {
		perror("pipe");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		struct sigaction sa = {
			.sa_handler = trigger_getpid,
		};

		close(ready[0]);
		if (setsid() < 0)
			exit(1);

		if (sigaction(SIGUSR1, &sa, NULL))
			exit(1);

		if (install_seccomp())
			exit(1);

		if (write(ready[1], "R", 1) != 1)
			exit(1);

		while (1)
			pause();
	}

	close(ready[1]);
	if (read(ready[0], &c, 1) != 1) {
		perror("read ready");
		goto err;
	}
	close(ready[0]);

	init_criu(argv[1], dir_fd, "dump.log");
	criu_set_pid(pid);
	ret = criu_dump();
	if (ret) {
		what_err_ret_mean(ret);
		goto err;
	}
	{
		char inventory[PATH_MAX];

		snprintf(inventory, sizeof(inventory), "%s/inventory.img", argv[2]);
		if (access(inventory, F_OK)) {
			perror("dump did not create inventory.img");
			goto err;
		}
	}

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	if (setenv("CRIU_FAULT", CRIU_FAULT_SECCOMP_NO_IMAGE_FILTERS, 1)) {
		perror("setenv CRIU_FAULT");
		goto err;
	}

	init_criu(argv[1], dir_fd, "restore.log");
	if (criu_set_seccomp_bpf(deny_getpid_filter, sizeof(deny_getpid_filter))) {
		perror("criu_set_seccomp_bpf");
		goto err;
	}

	pid = criu_restore_child();
	if (pid <= 0) {
		what_err_ret_mean(pid);
		goto err;
	}

	if (kill(pid, SIGUSR1)) {
		perror("signal restored child");
		goto err;
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("wait restore child");
		goto err;
	}

	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
		fprintf(stderr, "restored child did not hit external seccomp BPF, status %#x\n", status);
		return 1;
	}

	return 0;

err:
	if (pid > 0)
		kill(pid, SIGKILL);
	return 1;
}
