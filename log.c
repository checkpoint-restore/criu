#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <fcntl.h>

#include "compiler.h"
#include "types.h"
#include "util.h"
#include "crtools.h"

#define DEFAULT_LOGLEVEL	LOG_WARN
#define DEFAULT_LOGFD		STDERR_FILENO

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static int current_logfd = DEFAULT_LOGFD;

int log_get_fd(void)
{
	return current_logfd;
}

int log_init(const char *output)
{
	int new_logfd = DEFAULT_LOGFD, sfd;

	sfd = get_service_fd(LOG_FD_OFF);
	if (sfd < 0) {
		pr_msg("Can't obtain logfd");
		goto err;
	}

	if (output) {
		new_logfd = open(output, O_CREAT | O_WRONLY, 0600);
		if (new_logfd < 0) {
			pr_perror("Can't create log file %s", output);
			return -1;
		}
	}

	if (reopen_fd_as(sfd, new_logfd) < 0)

	current_logfd = sfd;

	return 0;

err:
	pr_perror("Log engine failure, can't duplicate descriptor");
	return -1;
}

void log_fini(void)
{
	if (current_logfd > 2)
		close_safe(&current_logfd);

	current_logfd = DEFAULT_LOGFD;
}

void log_set_loglevel(unsigned int level)
{
	if (!level)
		current_loglevel = DEFAULT_LOGLEVEL;
	else
		current_loglevel = level;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;
	int fd;

	if (unlikely(loglevel == LOG_MSG)) {
		fd = STDOUT_FILENO;
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = current_logfd;
	}

	va_start(params, format);
	vdprintf(fd, format, params);
	va_end(params);
}
