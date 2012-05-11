#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#include "zdtmtst.h"

static struct {
	char buffer[LOG_BUF_SIZE];
	char *ptr;
	int left;
} msg_buf = {
	.buffer = {},
	.ptr = msg_buf.buffer,
	.left = sizeof(msg_buf.buffer),
};

void test_msg(const char *format, ...)
{
	va_list arg;
	int len;

	va_start(arg, format);
	len = vsnprintf(msg_buf.ptr, msg_buf.left, format, arg);
	va_end(arg);

	if (len >= msg_buf.left) {	/* indicate message buffer overflow */
		const char overflow_mark[] = "\n.@.\n";
		msg_buf.left = 0;
		msg_buf.ptr = msg_buf.buffer + sizeof(msg_buf.buffer);
		strcpy(msg_buf.ptr - sizeof(overflow_mark), overflow_mark);
		msg_buf.ptr--;		/* correct for terminating '\0' */
		return;
	}

	msg_buf.ptr += len;
	msg_buf.left -= len;
}

extern int proc_id;

void dump_msg(const char *fname)
{
	if (msg_buf.ptr != msg_buf.buffer) {
		int fd;
		if (proc_id == 0) {
			fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0644);
		} else {
			char fname_child[1000];
			snprintf(fname_child,1000,"%s.%d",fname,proc_id);
			fd = open(fname_child, O_WRONLY | O_CREAT | O_APPEND, 0644);
		}
		if (fd < 0)
			return;
		/* ignore errors as there's no way to report them */
		write(fd, msg_buf.buffer, msg_buf.ptr - msg_buf.buffer);
		close(fd);
	}
}
