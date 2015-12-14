#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check for /proc/self/loginuid restore";
const char *test_author = "Dmitry Safonov <dsafonov@odin.com>";

const char loginuid_self[] = "/proc/self/loginuid";
const uid_t test_value = 3;
const uid_t INVALID_UID = (uid_t)-1;

uid_t get_loginuid(const char *path, int *err)
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

int set_loginuid(const char *path, uid_t value)
{
	int fd, ret = 0;
	char buf[11];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	snprintf(buf, 11, "%u", value);

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
	uid_t new_loginuid;

	/* unset before test */
	if (set_loginuid(loginuid_self, INVALID_UID) < 0)
		return -1;

	test_init(argc, argv);

	if (set_loginuid(loginuid_self, test_value) < 0)
		return -1;

	test_daemon();
	test_waitsig();

	new_loginuid = get_loginuid(loginuid_self, &ret);
	if (ret < 0)
		return -1;

	if (new_loginuid != test_value) {
		fail("loginuid value %d is different after restore: %d\n",
				test_value, new_loginuid);
		return -1;
	}

	pass();
	return 0;
}
