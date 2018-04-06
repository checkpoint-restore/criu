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
#include <sys/utsname.h>

#include <fcntl.h>

#include "page.h"
#include "common/compiler.h"
#include "util.h"
#include "cr_options.h"
#include "servicefd.h"
#include "rst-malloc.h"
#include "common/lock.h"
#include "string.h"
#include "version.h"

#include "../soccr/soccr.h"
#include "compel/log.h"


#define DEFAULT_LOGFD		STDERR_FILENO
/* Enable timestamps if verbosity is increased from default */
#define LOG_TIMESTAMP		(DEFAULT_LOGLEVEL + 1)

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;

static char buffer[PAGE_SIZE * 2];
static char buf_off = 0;

static struct timeval start;
/*
 * Manual buf len as sprintf will _always_ put '\0' at the end,
 * but we want a "constant" pid to be there on restore
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
	int fd = get_service_fd(LOG_FD_OFF);

	return fd < 0 ? DEFAULT_LOGFD : fd;
}

void log_get_logstart(struct timeval *s)
{
	if (current_loglevel >= LOG_TIMESTAMP)
		*s = start;
	else {
		s->tv_sec = 0;
		s->tv_usec = 0;
	}
}

static void reset_buf_off(void)
{
	if (current_loglevel >= LOG_TIMESTAMP)
		/* reserve space for a timestamp */
		buf_off = TS_BUF_OFF;
	else
		buf_off = 0;
}

/*
 * Keeping the very first error messsage for RPC to report back.
 */
struct str_and_lock {
	mutex_t l;
	char s[1024];
};

static struct str_and_lock *first_err;

int log_keep_err(void)
{
	first_err = shmalloc(sizeof(struct str_and_lock));
	if (first_err == NULL)
		return -1;

	mutex_init(&first_err->l);
	first_err->s[0] = '\0';
	return 0;
}

static void log_note_err(char *msg)
{
	if (first_err && first_err->s[0] == '\0') {
		/*
		 * In any action other than restore this locking is
		 * actually not required, but ... it's error path
		 * anyway, so it doesn't make much sense to try hard
		 * and optimize this out.
		 */
		mutex_lock(&first_err->l);
		if (first_err->s[0] == '\0')
			strlcpy(first_err->s, msg, sizeof(first_err->s));
		mutex_unlock(&first_err->l);
	}
}

char *log_first_err(void)
{
	if (!first_err)
		return NULL;
	if (first_err->s[0] == '\0')
		return NULL;

	return first_err->s;
}

static void print_versions(void)
{
	struct utsname buf;

	pr_info("Version: %s (gitid %s)\n", CRIU_VERSION, CRIU_GITID);

	if (uname(&buf) < 0) {
		pr_perror("Reading kernel version failed!");
		/* This pretty unlikely, just keep on running. */
		return;
	}

	pr_info("Running on %s %s %s %s %s\n", buf.nodename, buf.sysname,
		buf.release, buf.version, buf.machine);
}

int log_init(const char *output)
{
	int new_logfd, fd;

	gettimeofday(&start, NULL);
	reset_buf_off();

	if (output && !strncmp(output, "-", 2)) {
		new_logfd = dup(STDOUT_FILENO);
		if (new_logfd < 0) {
			pr_perror("Can't dup stdout stream");
			return -1;
		}
	} else if (output) {
		new_logfd = open(output, O_CREAT|O_TRUNC|O_WRONLY|O_APPEND, 0600);
		if (new_logfd < 0) {
			pr_perror("Can't create log file %s", output);
			return -1;
		}
	} else {
		new_logfd = dup(DEFAULT_LOGFD);
		if (new_logfd < 0) {
			pr_perror("Can't dup log file");
			return -1;
		}
	}

	fd = install_service_fd(LOG_FD_OFF, new_logfd);
	close(new_logfd);
	if (fd < 0)
		goto err;

	print_versions();

	return 0;

err:
	pr_perror("Log engine failure, can't duplicate descriptor");
	return -1;
}

int log_init_by_pid(pid_t pid)
{
	char path[PATH_MAX];

	/*
	 * reset buf_off as this fn is called on each fork while
	 * restoring process tree
	 */
	reset_buf_off();

	if (!opts.log_file_per_pid) {
		buf_off += snprintf(buffer + buf_off, sizeof buffer - buf_off, "%6d: ", pid);
		return 0;
	}

	if (!opts.output)
		return 0;

	snprintf(path, PATH_MAX, "%s.%d", opts.output, pid);

	return log_init(path);
}

void log_fini(void)
{
	close_service_fd(LOG_FD_OFF);
}

static void soccr_print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;
	int lv;

	switch (loglevel) {
	case SOCCR_LOG_DBG:
		lv = LOG_DEBUG;
		break;
	case SOCCR_LOG_ERR:
		lv = LOG_ERROR;
		break;
	default:
		lv = LOG_INFO;
		break;
	}

	va_start(args, format);
	vprint_on_level(lv, format, args);
	va_end(args);
}

void log_set_loglevel(unsigned int level)
{
	current_loglevel = level;

	libsoccr_set_log(level, soccr_print_on_level);
	compel_log_init(vprint_on_level, level);
}

unsigned int log_get_loglevel(void)
{
	return current_loglevel;
}

void vprint_on_level(unsigned int loglevel, const char *format, va_list params)
{
	int fd, size, ret, off = 0;
	int __errno = errno;

	if (unlikely(loglevel == LOG_MSG)) {
		fd = STDOUT_FILENO;
		off = buf_off; /* skip dangling timestamp */
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = log_get_fd();
		if (current_loglevel >= LOG_TIMESTAMP)
			print_ts();
	}

	size  = vsnprintf(buffer + buf_off, sizeof buffer - buf_off, format, params);
	size += buf_off;

	while (off < size) {
		ret = write(fd, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}

	if (loglevel == LOG_ERROR)
		log_note_err(buffer + buf_off);

	errno =  __errno;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	va_start(params, format);
	vprint_on_level(loglevel, format, params);
	va_end(params);
}

int write_pidfile(int pid)
{
	int fd;

	fd = open(opts.pidfile, O_WRONLY | O_EXCL | O_CREAT, 0600);
	if (fd == -1) {
		pr_perror("Can't open %s", opts.pidfile);
		return -1;
	}

	dprintf(fd, "%d", pid);
	close(fd);
	return 0;
}
