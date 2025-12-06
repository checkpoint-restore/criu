#include "criu.h"
#include "lib.h"

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>

#define RANDOM_NAME_LEN 6
#define PATH_BUF_SIZE	128

static volatile sig_atomic_t stop = 0;
static char base_name[RANDOM_NAME_LEN + 1];
static char log_file[PATH_BUF_SIZE];
static char conf_file[PATH_BUF_SIZE];

static void handle_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static void generate_random_base_name(void)
{
	const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t charset_len;
	int i;

	charset_len = sizeof(charset) - 1;

	for (i = 0; i < RANDOM_NAME_LEN; i++) {
		base_name[i] = charset[rand() % charset_len];
	}
	base_name[i] = '\0';

	snprintf(log_file, sizeof(log_file), "/tmp/criu-%s.log", base_name);
	snprintf(conf_file, sizeof(conf_file), "/tmp/criu-%s.conf", base_name);
}

static int create_criu_config_file(void)
{
	int fd;
	FILE *fp;

	srand(time(NULL));
	generate_random_base_name();

	fd = open(conf_file, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0) {
		perror("Failed to create config file");
		return -1;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		perror("fdopen failed");
		close(fd);
		unlink(conf_file);
		return -1;
	}

	fprintf(fp, "log-file=%s\n", log_file);
	fflush(fp);
	fclose(fp);

	return 0;
}

static int check_log_file(void)
{
	struct stat st;

	if (stat(log_file, &st) < 0) {
		perror("Config file does not exist");
		return -1;
	}

	if (st.st_size == 0) {
		fprintf(stderr, "Config file is empty\n");
		return -1;
	}

	unlink(log_file);
	return 0;
}

int main(int argc, char **argv)
{
	int pipe_fd[2];
	pid_t pid;
	int ret;
	int child_ret;

	int img_fd = open(argv[2], O_DIRECTORY);
	if (img_fd < 0) {
		perror("Failed to open images directory");
		goto cleanup;
	}

	if (create_criu_config_file() < 0) {
		printf("Failed to create config file\n");
		return EXIT_FAILURE;
	}

	if (pipe(pipe_fd) < 0) {
		perror("pipe");
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork failed");
		return EXIT_FAILURE;
	}

	if (pid == 0) {
		/** child process **/
		printf("   `- loop: initializing\n");

		if (setsid() < 0 || signal(SIGUSR1, handle_signal) == SIG_ERR) {
			_exit(EXIT_FAILURE);
		}

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		close(pipe_fd[0]);

		child_ret = SUCC_ECODE;
		write(pipe_fd[1], &child_ret, sizeof(child_ret));
		close(pipe_fd[1]);

		while (!stop) {
			sleep(1);
		}

		_exit(SUCC_ECODE);
	}

	/** parent process **/
	close(pipe_fd[1]);

	ret = -1;
	if (read(pipe_fd[0], &ret, sizeof(ret)) != sizeof(ret) || ret != SUCC_ECODE) {
		printf("Error starting loop\n");
		goto cleanup;
	}

	read(pipe_fd[0], &ret, 1);
	close(pipe_fd[0]);

	printf("--- Loop process started (pid: %d) ---\n", pid);

	printf("--- Checkpoint ---\n");
	criu_init_opts();
	criu_set_service_binary(argv[1]);
	criu_set_images_dir_fd(img_fd);
	criu_set_pid(pid);
	criu_set_log_level(CRIU_LOG_DEBUG);

	/* The RPC config file should overwrite the log-file set below */
	printf("Setting dump RPC config file: %s\n", conf_file);
	criu_set_config_file(conf_file);
	criu_set_log_file("dump.log");

	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		kill(pid, SIGKILL);
		printf("criu dump failed\n");
		goto cleanup;
	}

	printf("   `- Dump succeeded\n");
	waitpid(pid, NULL, 0);

	if (check_log_file()) {
		printf("Error: log file not overwritten by RPC config file\n");
		goto cleanup;
	}

	printf("--- Restore loop ---\n");
	criu_init_opts();
	criu_set_images_dir_fd(img_fd);
	criu_set_log_level(CRIU_LOG_DEBUG);

	/* The RPC config file should overwrite the log-file set below */
	printf("Setting restore RPC config file: %s\n", conf_file);
	criu_set_config_file(conf_file);
	criu_set_log_file("restore.log");

	pid = criu_restore_child();
	if (pid <= 0) {
		what_err_ret_mean(pid);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	printf("   `- Restore returned pid %d\n", pid);
	kill(pid, SIGUSR1);

	if (check_log_file()) {
		printf("Error: log file not overwritten by RPC config file\n");
		goto cleanup;
	}

cleanup:
	if (waitpid(pid, &ret, 0) < 0) {
		perror("waitpid failed");
		return EXIT_FAILURE;
	}

	printf("Remove RPC config file: %s\n", conf_file);
	unlink(conf_file);
	return chk_exit(ret, SUCC_ECODE);
}
