#ifndef CUDA_MOCK_H
#define CUDA_MOCK_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Make a failure happen once across helpers and CRIU's fault retry. */
static inline bool mock_failure(void)
{
	const char *path = getenv("CRIU_CUDA_MOCK_ONCE");
	int fd;

	if (!path)
		return true;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		if (errno == EEXIST)
			return false;
		perror("Unable to create CUDA mock failure marker");
		_exit(1);
	}
	if (close(fd))
		_exit(1);
	return true;
}

#endif
