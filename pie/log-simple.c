#include <stdarg.h>
#include "syscall.h"
#include "log.h"
#include "log-levels.h"

static int logfd = -1;
static int cur_loglevel = DEFAULT_LOGLEVEL;

void log_set_fd(int fd)
{
	sys_close(logfd);
	logfd = fd;
}

void log_set_loglevel(unsigned int level)
{
	cur_loglevel = level;
}

static void print_string(const char *msg)
{
	int size = 0;
	while (msg[size])
		size++;
	sys_write(logfd, msg, size);
}

int vprint_num(char *buf, int blen, int num, char **ps)
{
	int neg = 0;
	char *s;

	s = &buf[blen - 1];

	if (num < 0) {
		neg = 1;
		num = -num;
	} else if (num == 0) {
		*s = '0';
		s--;
		goto done;
	}

	while (num > 0) {
		*s = (num % 10) + '0';
		s--;
		num /= 10;
	}

	if (neg) {
		*s = '-';
		s--;
	}
done:
	s++;
	*ps = s;
	return blen - (s - buf);
}

static void print_num(int num)
{
	char buf[11], *s;
	int len;

	len = vprint_num(buf, sizeof(buf), num, &s);
	sys_write(logfd, s, len);
}

static void print_num_l(long num)
{
	int neg = 0;
	char buf[21], *s;

	s = &buf[20];

	if (num < 0) {
		neg = 1;
		num = -num;
	} else if (num == 0) {
		*s = '0';
		s--;
		goto done;
	}

	while (num > 0) {
		*s = (num % 10) + '0';
		s--;
		num /= 10;
	}

	if (neg) {
		*s = '-';
		s--;
	}
done:
	s++;
	sys_write(logfd, s, sizeof(buf) - (s - buf));
}

static void hexdigit(unsigned int v, char *to, char **z)
{
	*to = "0123456789abcdef"[v & 0xf];
	if (*to != '0')
		*z = to;
}

static void print_hex(unsigned int num)
{
	char buf[10], *z = &buf[9];

	hexdigit(num >> 0, &buf[9], &z);
	hexdigit(num >> 4, &buf[8], &z);
	hexdigit(num >> 8, &buf[7], &z);
	hexdigit(num >> 12, &buf[6], &z);
	hexdigit(num >> 16, &buf[5], &z);
	hexdigit(num >> 20, &buf[4], &z);
	hexdigit(num >> 24, &buf[3], &z);
	hexdigit(num >> 28, &buf[2], &z);
	z -= 2;
	z[0] = '0';
	z[1] = 'x';

	sys_write(logfd, z, sizeof(buf) - (z - buf));
}

static void print_hex_l(unsigned long num)
{
	char buf[18], *z = &buf[17];

	hexdigit(num >> 0, &buf[17], &z);
	hexdigit(num >> 4, &buf[16], &z);
	hexdigit(num >> 8, &buf[15], &z);
	hexdigit(num >> 12, &buf[14], &z);
	hexdigit(num >> 16, &buf[13], &z);
	hexdigit(num >> 20, &buf[12], &z);
	hexdigit(num >> 24, &buf[11], &z);
	hexdigit(num >> 28, &buf[10], &z);

#if BITS_PER_ULONG == 64
	hexdigit(num >> 32, &buf[9], &z);
	hexdigit(num >> 36, &buf[8], &z);
	hexdigit(num >> 40, &buf[7], &z);
	hexdigit(num >> 44, &buf[6], &z);
	hexdigit(num >> 48, &buf[5], &z);
	hexdigit(num >> 52, &buf[4], &z);
	hexdigit(num >> 56, &buf[3], &z);
	hexdigit(num >> 60, &buf[2], &z);
#endif

	z -= 2;
	z[0] = '0';
	z[1] = 'x';

	sys_write(logfd, z, sizeof(buf) - (z - buf));
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;
	const char *s = format, *p;

	if (loglevel > cur_loglevel)
		return;

	va_start(args, format);
	p = s;
	while (1) {
		int along = 0;

		if (*s != '\0' && *s != '%') {
			s++;
			continue;
		}

		sys_write(logfd, p, s - p);
		if (*s == '\0')
			break;

		s++;
		if (*s == 'l') {
			along = 1;
			s++;
		}

		switch (*s) {
		case 's':
			print_string(va_arg(args, char *));
			break;
		case 'd':
			if (along)
				print_num_l(va_arg(args, long));
			else
				print_num(va_arg(args, int));
			break;
		case 'x':
			if (along)
				print_hex_l(va_arg(args, long));
			else
				print_hex(va_arg(args, unsigned int));
			break;
		}
		s++;
		p = s;
	}
	va_end(args);
}
