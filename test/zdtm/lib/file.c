#include <fcntl.h>
#include <unistd.h>
#include "zdtmtst.h"

int write_value(const char *path, const char *value)
{
	int fd, l;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("open %s", path);
		return -1;
	}

	l = write(fd, value, strlen(value));
	if (l < 0) {
		pr_perror("failed to write %s to %s", value, path);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int read_value(const char *path, char *value, int size)
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("open %s", path);
		return -1;
	}

	ret = read(fd, (void *)value, size);
	if (ret < 0) {
		pr_perror("read %s", path);
		close(fd);
		return -1;
	}

	value[ret] = '\0';
	close(fd);
	return 0;
}
