#include <stdarg.h>

#include "common/bitsperlong.h"
#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/string.h>
#include <compel/plugins/std/log.h>
#include <compel/loglevels.h>

struct simple_buf {
	char buf[STD_LOG_SIMPLE_CHUNK];
	char *bp;
	int prefix_len;
	void (*flush)(struct simple_buf *b);
};

static int logfd = -1;
static int cur_loglevel = COMPEL_DEFAULT_LOGLEVEL;
static struct timeval start;
static gettimeofday_t __std_gettimeofday;

static void sbuf_log_flush(struct simple_buf *b);

static inline void timediff(struct timeval *from, struct timeval *to)
{
	to->tv_sec -= from->tv_sec;
	if (to->tv_usec >= from->tv_usec)
		to->tv_usec -= from->tv_usec;
	else {
		to->tv_sec--;
		to->tv_usec += 1000000 - from->tv_usec;
	}
}

static inline void pad_num(char **s, int *n, int nr)
{
	while (*n < nr) {
		(*s)--;
		(*n)++;
		**s = '0';
	}
}

static void sbuf_log_init(struct simple_buf *b)
{
	char pbuf[12], *s;
	int n;

	/*
	 * Format:
	 *
	 * (time)pie: pid: string-itself
	 */
	b->bp = b->buf;

	if (start.tv_sec != 0) {
		struct timeval now;

		std_gettimeofday(&now, NULL);
		timediff(&start, &now);

		/* Seconds */
		n = std_vprint_num(pbuf, sizeof(pbuf), (unsigned)now.tv_sec, &s);
		pad_num(&s, &n, 2);
		b->bp[0] = '(';
		memcpy(b->bp + 1, s, n);
		b->bp[n + 1] = '.';
		b->bp += n + 2;

		/* Mu-seconds */
		n = std_vprint_num(pbuf, sizeof(pbuf), (unsigned)now.tv_usec, &s);
		pad_num(&s, &n, 6);
		memcpy(b->bp, s, n);
		b->bp[n++] = ')';
		b->bp[n++] = ' ';
		b->bp += n;
	}

	n = std_vprint_num(pbuf, sizeof(pbuf), sys_gettid(), &s);
	b->bp[0] = 'p';
	b->bp[1] = 'i';
	b->bp[2] = 'e';
	b->bp[3] = ':';
	b->bp[4] = ' ';
	memcpy(b->bp + 5, s, n);
	b->bp[n + 5] = ':';
	b->bp[n + 6] = ' ';
	b->bp += n + 7;
	b->prefix_len = b->bp - b->buf;
	b->flush = sbuf_log_flush;
}

static void sbuf_log_flush(struct simple_buf *b)
{
	if (b->bp == b->buf + b->prefix_len)
		return;

	sys_write(logfd, b->buf, b->bp - b->buf);
	b->bp = b->buf + b->prefix_len;
}

static void sbuf_putc(struct simple_buf *b, char c)
{
	/* TODO: maybe some warning or error here? */
	if (b->bp - b->buf >= STD_LOG_SIMPLE_CHUNK)
		return;

	*b->bp = c;
	b->bp++;
	if (b->bp - b->buf >= STD_LOG_SIMPLE_CHUNK - 2) {
		b->bp[0] = '>';
		b->bp[1] = '\n';
		b->bp += 2;
		if (b->flush)
			b->flush(b);
	}
}

void std_log_set_fd(int fd)
{
	sys_close(logfd);
	logfd = fd;
}

void std_log_set_loglevel(enum __compel_log_levels level)
{
	cur_loglevel = level;
}

void std_log_set_start(struct timeval *s)
{
	start = *s;
}

void std_log_set_gettimeofday(gettimeofday_t gtod)
{
	__std_gettimeofday = gtod;
}

int std_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if (__std_gettimeofday != NULL)
		return __std_gettimeofday(tv, tz);

	return sys_gettimeofday(tv, tz);
}

static void print_string(const char *msg, struct simple_buf *b)
{
	while (*msg) {
		sbuf_putc(b, *msg);
		msg++;
	}
}

int std_vprint_num(char *buf, int blen, int num, char **ps)
{
	int neg = 0;
	char *s;

	s = &buf[blen - 1];
	*s-- = 0; /* make sure the returned string is NULL terminated */

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
	return blen - (s - buf) - 1;
}

static void print_num(int num, struct simple_buf *b)
{
	char buf[12], *s;

	std_vprint_num(buf, sizeof(buf), num, &s);
	print_string(s, b);
}

static void print_num_l(long num, struct simple_buf *b)
{
	int neg = 0;
	char buf[22], *s;

	buf[21] = '\0';
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
	print_string(s, b);
}

static void hexdigit(unsigned int v, char *to, char **z)
{
	*to = "0123456789abcdef"[v & 0xf];
	if (*to != '0')
		*z = to;
}

static void print_hex(unsigned int num, struct simple_buf *b)
{
	char buf[11], *z = &buf[9];

	buf[10] = '\0';
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

	print_string(z, b);
}

static void print_hex_l(unsigned long num, struct simple_buf *b)
{
	char buf[19], *z = &buf[17];

	buf[18] = '\0';
	hexdigit(num >> 0, &buf[17], &z);
	hexdigit(num >> 4, &buf[16], &z);
	hexdigit(num >> 8, &buf[15], &z);
	hexdigit(num >> 12, &buf[14], &z);
	hexdigit(num >> 16, &buf[13], &z);
	hexdigit(num >> 20, &buf[12], &z);
	hexdigit(num >> 24, &buf[11], &z);
	hexdigit(num >> 28, &buf[10], &z);

#if BITS_PER_LONG == 64
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

	print_string(z, b);
}

static void sbuf_printf(struct simple_buf *b, const char *format, va_list args)
{
	const char *s = format;
	while (1) {
		int along = 0;

		if (*s == '\0')
			break;

		if (*s != '%') {
			sbuf_putc(b, *s);
			s++;
			continue;
		}

		s++;
		if (*s == 'l') {
			along = 1;
			s++;
			if (*s == 'l')
				s++;
		} else if (*s == 'z') {
			along = (sizeof(size_t) > sizeof(int));
			s++;
		}

		switch (*s) {
		case 's':
			print_string(va_arg(args, char *), b);
			break;
		case 'd':
			if (along)
				print_num_l(va_arg(args, long), b);
			else
				print_num(va_arg(args, int), b);
			break;
		case 'x':
			if (along)
				print_hex_l(va_arg(args, long), b);
			else
				print_hex(va_arg(args, unsigned int), b);
			break;
		case 'p':
			print_hex_l((unsigned long)va_arg(args, void *), b);
			break;
		default:
			print_string("UNKNOWN FORMAT ", b);
			sbuf_putc(b, *s);
			break;
		}
		s++;
	}
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;
	struct simple_buf b;

	if (loglevel > cur_loglevel)
		return;

	sbuf_log_init(&b);

	va_start(args, format);
	sbuf_printf(&b, format, args);
	va_end(args);

	sbuf_log_flush(&b);
}

void std_sprintf(char output[STD_LOG_SIMPLE_CHUNK], const char *format, ...)
{
	va_list args;
	struct simple_buf b;
	char *p;

	b.bp = b.buf;
	b.flush = NULL;

	va_start(args, format);
	sbuf_printf(&b, format, args);
	va_end(args);
	*b.bp = 0;

	for (p = b.buf; p <= b.bp; p++)
		output[p - b.buf] = *p;
}
