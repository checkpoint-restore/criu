#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check pipe data survives C/R when pipe resize is denied";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

int main(int argc, char **argv)
{
	uint8_t *buf = NULL;
	uint32_t crc = ~0U;
	int default_size, data_size, pipe_size, restored_size;
	int p[2];
	int ret = 1;

	test_init(argc, argv);

	if (pipe2(p, O_NONBLOCK)) {
		pr_perror("pipe");
		return 1;
	}

	default_size = fcntl(p[1], F_GETPIPE_SZ);
	if (default_size < 0) {
		pr_perror("Unable to get default pipe size");
		goto out;
	}

	data_size = default_size / 2;
	pipe_size = default_size * 2;
	buf = malloc(data_size);
	if (!buf) {
		pr_perror("malloc");
		goto out;
	}

	if (fcntl(p[1], F_SETPIPE_SZ, pipe_size) == -1) {
		pr_perror("Unable to change pipe size");
		goto out;
	}

	datagen(buf, data_size, &crc);

	if (write(p[1], buf, data_size) != data_size) {
		pr_perror("write");
		goto out;
	}

	test_daemon();
	test_waitsig();

	restored_size = fcntl(p[1], F_GETPIPE_SZ);
	if (restored_size < 0) {
		pr_perror("Unable to get restored pipe size");
		goto out;
	}
	if (restored_size >= pipe_size) {
		fail("pipe size unexpectedly restored despite denied resize");
		goto out;
	}

	if (read(p[0], buf, data_size) != data_size) {
		pr_perror("read");
		goto out;
	}

	crc = ~0U;
	if (datachk(buf, data_size, &crc)) {
		fail("pipe data corrupted after C/R");
		goto out;
	}

	pass();
	ret = 0;

out:
	free(buf);
	close(p[0]);
	close(p[1]);
	return ret;
}
