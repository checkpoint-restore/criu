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

#define DEFAULT_LOGFD		STDERR_FILENO

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static int current_logfd = DEFAULT_LOGFD;
static int logdir = -1;

static char buffer[PAGE_SIZE];
static char buf_off = 0;

static struct timeval start;
/*
 * Manual buf len as sprintf will _always_ put '\0' at the
 * and, but we want a "constant" pid to be there on restore
 */
#define TS_BUF_OFF	12

static void timediff(struct timeval *from, struct timeval *to)
{
	to->tv_sec -= from->tv_sec;
	if (to->tv_usec >= from->tv_usec)
		to->tv_usec -= from->tv_usec;
	else {
		to->tv_sec--;
		to->tv_usec += 1000000 - from->tv_usec;
	}
}

static void print_ts(void)
{
	struct timeval t;

	gettimeofday(&t, NULL);
	timediff(&start, &t);
	snprintf(buffer, TS_BUF_OFF,
			"(%02u.%06u)", (unsigned)t.tv_sec, (unsigned)t.tv_usec);
	buffer[TS_BUF_OFF - 1] = ' '; /* kill the '\0' produced by snprintf */
}



int log_get_fd(void)
{
	return current_logfd;
}

int log_init(const char *output)
{
	int new_logfd, sfd, dfd;

	gettimeofday(&start, NULL);
	buf_off = TS_BUF_OFF;

	dfd = get_service_fd(LOG_DIR_FD_OFF);
	if (dfd < 0) {
		pr_msg("Can't obtain logfd");
		goto err;
	}

	if (logdir < 0) {
		int tmp;
		tmp = open(".", O_RDONLY);
		if (tmp == -1) {
			pr_perror("Can't open a current directory");
			return -1;
		}

		if (reopen_fd_as(dfd, tmp) < 0)
			return -1;

		logdir = dfd;
	}

	sfd = get_service_fd(LOG_FD_OFF);
	if (sfd < 0) {
		pr_msg("Can't obtain logfd");
		goto err;
	}

	if (output) {
		new_logfd = openat(logdir, output,
					O_CREAT | O_TRUNC | O_WRONLY | O_APPEND, 0600);
		if (new_logfd < 0) {
			pr_perror("Can't create log file %s", output);
			return -1;
		}

		if (sfd == current_logfd)
			close(sfd);

		if (reopen_fd_as(sfd, new_logfd) < 0)
			goto err;
	} else {
		new_logfd = dup2(DEFAULT_LOGFD, sfd);
		if (new_logfd < 0) {
			pr_perror("Dup %d -> %d failed", DEFAULT_LOGFD, sfd);
			goto err;
		}
	}

	current_logfd = sfd;

	return 0;

err:
	pr_perror("Log engine failure, can't duplicate descriptor");
	return -1;
}

int log_init_by_pid(void)
{
	char path[PATH_MAX];

	/*
	 * reset buf_off as this fn is called on each fork while
	 * restoring process tree
	 */

	buf_off = TS_BUF_OFF;

	if (!opts.log_file_per_pid) {
		buf_off += snprintf(buffer + buf_off, PAGE_SIZE - buf_off, "%6d: ", getpid());
		return 0;
	}

	if (!opts.output)
		return 0;

	snprintf(path, PATH_MAX, "%s.%d", opts.output, getpid());

	return log_init(path);
}

void log_fini(void)
{
	if (current_logfd > 2)
		close_safe(&current_logfd);

	current_logfd = DEFAULT_LOGFD;
}

void log_closedir(void)
{
	close_safe(&logdir);
}

void log_set_loglevel(unsigned int level)
{
	if (!level)
		current_loglevel = DEFAULT_LOGLEVEL;
	else
		current_loglevel = level;
}

unsigned int log_get_loglevel(void)
{
	return current_loglevel;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;
	int fd, size, ret, off;

	if (unlikely(loglevel == LOG_MSG)) {
		fd = STDOUT_FILENO;
		off = buf_off;
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = current_logfd;
		print_ts();
		off = 0;
	}

	va_start(params, format);
	size = vsnprintf(buffer + buf_off, PAGE_SIZE - buf_off, format, params);
	va_end(params);

	size += buf_off;

	while (off < size) {
		ret = write(fd, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}
}
