#include "criu.h"
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

static void what_err_ret_mean(ret)
{
	/* NOTE: errno is set by libcriu */
	switch (ret) {
	case -EBADE:
		perror("RPC has returned fail");
		break;
	case -ECONNREFUSED:
		perror("Unable to connect to CRIU");
		break;
	case -ECOMM:
		perror("Unable to send/recv msg to/from CRIU");
		break;
	case -EINVAL:
		perror("CRIU doesn't support this type of request."
		       "You should probably update CRIU");
		break;
	case -EBADMSG:
		perror("Unexpected response from CRIU."
		       "You should probably update CRIU");
		break;
	default:
		perror("Unknown error type code."
		       "You should probably update CRIU");
	}
}

int main(int argc, char *argv[])
{
	int ret, fd;

	criu_set_service_address("criu_service.socket");

	puts("--- Check ---");
	ret = criu_check();
	if (ret < 0) {
		what_err_ret_mean(ret);
		return -1;
	} else
		puts("Success");

	puts("--- Dump loop ---");
	criu_init_opts();
	criu_set_pid(atoi(argv[1]));
	criu_set_log_file("dump.log");
	criu_set_log_level(4);
	fd = open("imgs_loop", O_DIRECTORY);
	criu_set_images_dir_fd(fd);

	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		return -1;
	} else if (ret == 0)
		puts("Success");

	puts("--- Restore loop ---");
	criu_init_opts();
	criu_set_log_level(4);
	criu_set_log_file("restore.log");
	criu_set_images_dir_fd(fd);

	ret = criu_restore();
	if (ret < 0) {
		what_err_ret_mean(ret);
		return -1;
	} else if (ret > 0) {
		puts("Success");
		printf("pid %d\n", ret);
	}

	puts("--- Dump myself ---");
	criu_init_opts();
	criu_set_leave_running(true);
	criu_set_shell_job(true);
	criu_set_images_dir_fd(open("imgs_test", O_DIRECTORY));

	ret = criu_dump();
	if (ret < 0) {
		what_err_ret_mean(ret);
		return -1;
	} else {
		puts("Success");
		if (ret == 1)
			puts("Restored");
	}

	return 0;
}
