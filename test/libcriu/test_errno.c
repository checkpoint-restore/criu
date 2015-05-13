#include "criu.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define PID_MAX "/proc/sys/kernel/pid_max"

static int dir_fd;
static char *service;

static int init(char *argv[])
{
	service = argv[1];

	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd < 0) {
		perror("Can't open images dir");
		return -1;
	}

	return 0;
}

static void get_base_req(void)
{
	criu_init_opts();
	criu_set_service_address(service);
	criu_set_images_dir_fd(dir_fd);
	criu_set_log_level(4);
}

static int check_resp(int ret, int expected_ret, int err, int expected_err)
{
	if (ret != expected_ret) {
		fprintf(stderr, "Unexpected ret %d (%d expected)\n", ret, expected_ret);
		return -1;
	}

	if (err != expected_err) {
		fprintf(stderr, "Unexpected errno %d (%d expected)\n", err, expected_err);
		return -1;
	}

	return 0;
}

static int no_process(void)
{
	FILE *f = NULL;
	size_t len;
	ssize_t count;
	char *buf = NULL;
	int pid, fd, ret;

	printf("--- Try to dump unexisting process\n");

	f = fopen(PID_MAX, "r");
	if (!f) {
		perror("Can't open " PID_MAX);
		goto err;
	}

	count = getline(&buf, &len, f);
	if (count == -1) {
		perror("Can't read " PID_MAX);
		goto err;
	}
	pid = atoi(buf);

	if (!kill(pid, 0)) {
		fprintf(stderr, "max pid is taken\n");
		goto err;
	}

	get_base_req();
	criu_set_pid(pid);
	ret = criu_dump();
	if (check_resp(ret, -EBADE, errno, ESRCH))
		goto err;

	printf("   `- Success\n");
	return 0;
err:
	if (f)
		fclose(f);
	return -1;

}

static int process_exists(void)
{
	int ret;

	printf("--- Try to restore process which pid is already taken by other process\n");

	get_base_req();
	criu_set_leave_running(true);
	if (criu_dump()) {
		fprintf(stderr, "Self-dump failed");
		goto err;
	}

	get_base_req();
	ret = criu_restore();
	if (check_resp(ret, -EBADE, errno, EEXIST))
		goto err;

	printf("   `- Success\n");
	return 0;
err:
	return -1;
}

static int bad_options(void)
{
	int ret;

	printf("--- Try to send criu invalid opts\n");

	get_base_req();
	criu_set_log_file("../file.log");
	ret = criu_dump();
	if (check_resp(ret, -EBADE, errno, EBADRQC))
		goto err;

	printf("   `- Success\n");
	return 0;
err:
	return -1;
}

int main(int argc, char *argv[])
{
	int ret = 1;

	if (init(argv))
		goto out;

	if (no_process() || process_exists() || bad_options())
		goto out;

	ret = 0;
out:
	if (dir_fd)
		close(dir_fd);

	return ret;
}
