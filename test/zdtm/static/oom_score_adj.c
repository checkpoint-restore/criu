#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check for /proc/self/oom_score_adj restore";
const char *test_author = "Dmitry Safonov <dsafonov@odin.com>";

const char oom_score_adj_self[] = "/proc/self/oom_score_adj";
const int test_value = 400;

int get_oom_score_adj(const char *path, int *err)
{
	int fd;
	ssize_t num;
	char buf[11];

	*err = 0;
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		goto out;
	}

	num = read(fd, buf, 10);
	close(fd);
	if (num < 0) {
		pr_perror("Unable to read %s", path);
		goto out;
	}
	buf[num] = '\0';

	return strtol(buf, NULL, 10);

out:
	*err = -1;
	return 0;
}

int set_oom_score_adj(const char *path, int value)
{
	int fd, ret = 0;
	char buf[11];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	snprintf(buf, 11, "%d", value);

	if (write(fd, buf, 11) < 0) {
		pr_perror("Write %s to %s failed", buf, path);
		ret = -1;
	}

	close(fd);
	return ret;
}


int main(int argc, char *argv[])
{
	int ret;
	int new_oom_score_adj;

	test_init(argc, argv);

	if (set_oom_score_adj(oom_score_adj_self, test_value) < 0)
		return -1;

	test_daemon();
	test_waitsig();

	new_oom_score_adj = get_oom_score_adj(oom_score_adj_self, &ret);
	if (ret < 0)
		return -1;

	if (new_oom_score_adj != test_value) {
		fail("OOM score value %d is different after restore: %d\n",
				test_value, new_oom_score_adj);
		return -1;
	}

	pass();
	return 0;
}
