#define _GNU_SOURCE
#include "criu.h"
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib.h"

#define PS_ADDR	   "127.0.0.1"
#define PS_PORT	   27279
#define MEM_PAGES  4096
#define STACK_SIZE (1024 * 1024)

static int ready_fd = -1;
static int status_fd = -1;
static volatile sig_atomic_t stop = 0;

static void sh(int sig)
{
	stop = 1;
}

static unsigned char pattern(long page)
{
	return (page % 255) + 1;
}

/*
 * The dumped task is the init of its own pid namespace, as the original
 * task is still alive (frozen) while it is restored lazily.
 */
static int loop(void *arg)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned char *mem;
	long i, j;
	int ret;

	if (setsid() < 0)
		exit(1);
	if (signal(SIGUSR1, sh) == SIG_ERR)
		exit(1);

	mem = mmap(NULL, MEM_PAGES * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED)
		exit(1);
	for (i = 0; i < MEM_PAGES; i++)
		memset(mem + i * page_size, pattern(i), page_size);

	close(0);
	close(1);
	close(2);

	ret = SUCC_ECODE;
	write(ready_fd, &ret, sizeof(ret));
	close(ready_fd);

	while (!stop)
		sleep(1);

	/* Every page read here is served by the lazy-pages daemon. */
	for (i = 0; i < MEM_PAGES; i++)
		for (j = 0; j < page_size; j++)
			if (mem[i * page_size + j] != pattern(i))
				exit(1);

	exit(SUCC_ECODE);
}

static int notify(char *action, criu_notify_arg_t na)
{
	char c = 0;

	if (strcmp(action, "status-ready") == 0 && status_fd != -1) {
		if (write(status_fd, &c, 1) != 1)
			return -1;
		close(status_fd);
		status_fd = -1;
	}
	return 0;
}

static int wait_ready(int fd, const char *what)
{
	char c;

	if (read(fd, &c, 1) != 1) {
		printf("   `- %s is not ready\n", what);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int pid, dump_pid, lp_pid, rst_pid = -1;
	int ret, p[2], sp[2], lp[2], fd;
	char port[8], lp_status_fd[16];
	char *stack;

	fd = open(argv[2], O_DIRECTORY);
	if (fd < 0) {
		perror("Can't open images dir");
		return 1;
	}

	printf("--- Start loop ---\n");
	stack = malloc(STACK_SIZE);
	if (!stack || pipe(p)) {
		perror("Can't");
		return 1;
	}
	ready_fd = p[1];
	pid = clone(loop, stack + STACK_SIZE, CLONE_NEWPID | SIGCHLD, NULL);
	if (pid < 0) {
		perror("Can't clone");
		return 1;
	}
	close(p[1]);

	ret = -1;
	read(p[0], &ret, sizeof(ret));
	close(p[0]);
	if (ret != SUCC_ECODE) {
		printf("Error starting loop\n");
		goto err_loop;
	}

	printf("--- Lazy dump loop ---\n");
	if (pipe(sp)) {
		perror("Can't");
		goto err_loop;
	}
	dump_pid = fork();
	if (dump_pid < 0) {
		perror("Can't fork");
		goto err_loop;
	}
	if (!dump_pid) {
		close(sp[0]);
		status_fd = sp[1];

		criu_init_opts();
		criu_set_service_binary(argv[1]);
		criu_set_pid(pid);
		criu_set_images_dir_fd(fd);
		criu_set_log_file("dump.log");
		criu_set_log_level(CRIU_LOG_DEBUG);
		criu_set_lazy_pages(true);
		if (criu_set_page_server_address_port(PS_ADDR, PS_PORT)) {
			printf("Can't set page server address\n");
			exit(1);
		}
		criu_set_notify_cb(notify);

		/* Returns only after all pages are transferred. */
		ret = criu_dump();
		if (ret < 0) {
			what_err_ret_mean(ret);
			exit(1);
		}
		exit(0);
	}
	close(sp[1]);

	if (wait_ready(sp[0], "Page server"))
		goto err_dump;
	close(sp[0]);
	printf("   `- Page server is ready\n");

	printf("--- Start lazy-pages daemon ---\n");
	if (pipe(lp)) {
		perror("Can't");
		goto err_dump;
	}
	lp_pid = fork();
	if (lp_pid < 0) {
		perror("Can't fork");
		goto err_dump;
	}
	if (!lp_pid) {
		close(lp[0]);
		snprintf(port, sizeof(port), "%d", PS_PORT);
		snprintf(lp_status_fd, sizeof(lp_status_fd), "%d", lp[1]);
		execl(argv[1], argv[1], "lazy-pages", "--page-server", "--address", PS_ADDR, "--port", port,
		      "--status-fd", lp_status_fd, "-D", argv[2], "-o", "lazy-pages.log", "-v4", NULL);
		perror("Can't exec criu lazy-pages");
		exit(1);
	}
	close(lp[1]);

	if (wait_ready(lp[0], "Lazy-pages daemon"))
		goto err_lp;
	close(lp[0]);
	printf("   `- Lazy-pages daemon is ready\n");

	printf("--- Lazy restore ---\n");
	criu_init_opts();
	criu_set_service_binary(argv[1]);
	criu_set_images_dir_fd(fd);
	criu_set_log_file("restore.log");
	criu_set_log_level(CRIU_LOG_DEBUG);
	criu_set_lazy_pages(true);

	rst_pid = criu_restore_child();
	if (rst_pid <= 0) {
		what_err_ret_mean(rst_pid);
		goto err_lp;
	}
	printf("   `- Restore returned pid %d\n", rst_pid);

	/*
	 * The restored task is the init of its pid namespace, and it only
	 * gets this signal from the parent namespace as it has a handler.
	 */
	if (kill(rst_pid, SIGUSR1)) {
		perror("   Can't signal restored task");
		kill(rst_pid, SIGKILL);
		waitpid(rst_pid, NULL, 0);
		goto err_lp;
	}
	if (waitpid(rst_pid, &ret, 0) < 0) {
		perror("   Can't wait restored task");
		goto err_lp;
	}
	if (chk_exit(ret, SUCC_ECODE))
		goto err_lp;
	printf("   `- Restored task checked its memory\n");

	if (waitpid(lp_pid, &ret, 0) < 0 || chk_exit(ret, 0))
		goto err_dump;
	if (waitpid(dump_pid, &ret, 0) < 0 || chk_exit(ret, 0))
		goto err_loop;
	waitpid(pid, NULL, 0);

	printf("   `- Success\n");
	return 0;

err_lp:
	kill(lp_pid, SIGKILL);
	waitpid(lp_pid, NULL, 0);
err_dump:
	kill(dump_pid, SIGKILL);
	waitpid(dump_pid, NULL, 0);
err_loop:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 1;
}
