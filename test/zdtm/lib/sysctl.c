#include <fcntl.h>

#include "zdtmtst.h"
#include "sysctl.h"

int sysctl_read_int(const char *name, int *data)
{
	int fd;
	int ret;
	char buf[16];

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}

	buf[ret] = '\0';

	*data = (int)strtoul(buf, NULL, 10);
	ret = 0;
err:
	close(fd);
	return ret;
}

int sysctl_write_int(const char *name, int val)
{
	int fd;
	int ret;
	char buf[16];

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}

	sprintf(buf, "%d\n", val);

	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		pr_perror("Can't write %d into %s", val, name);
		ret = -errno;
		goto err;
	}

	ret = 0;
err:
	close(fd);
	return ret;
}
