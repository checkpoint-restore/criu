#include <stdarg.h>

#include "asm/bitsperlong.h"

#include "syscall.h"
#include "log.h"

#define LOG_SIMPLE_CHUNK	72

struct simple_buf {
	char buf[LOG_SIMPLE_CHUNK];
	char *bp;
};

static int logfd = -1;
static int cur_loglevel = DEFAULT_LOGLEVEL;

static void sbuf_init(struct simple_buf *b)
{
	b->buf[0] = 'p';
	b->buf[1] = 'i';
	b->buf[2] = 'e';
	b->buf[3] = ':';
	b->buf[4] = ' ';
	b->bp = b->buf + 5;
}

static void sbuf_flush(struct simple_buf *b)
{
	if (b->bp == b->buf + 5)
		return;

	sys_write(logfd, b->buf, b->bp - b->buf);
	sbuf_init(b);
}

static void sbuf_putc(struct simple_buf *b, char c)
{
	*b->bp = c;
	b->bp++;
	if (b->bp - b->buf >= LOG_SIMPLE_CHUNK - 2) {
		b->bp[0] = '>';
		b->bp[1] = '\n';
		b->bp += 2;
		sbuf_flush(b);
	}
}

void log_set_fd(int fd)
{
	sys_close(logfd);
	logfd = fd;
}

void log_set_loglevel(unsigned int level)
{
	cur_loglevel = level;
}

static void print_string(const char *msg, struct simple_buf *b)
{
	while (*msg) {
		sbuf_putc(b, *msg);
		msg++;
	}
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

static void print_num(int num, struct simple_buf *b)
{
	char buf[12], *s;

	buf[11] = '\0';
	vprint_num(buf, sizeof(buf) - 1, num, &s);
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

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;
	const char *s = format;
	struct simple_buf b;

	if (loglevel > cur_loglevel)
		return;

	sbuf_init(&b);

	va_start(args, format);
	while (1) {
		int along = 0;

		if (*s == '\0')
			break;

		if (*s != '%') {
			sbuf_putc(&b, *s);
			s++;
			continue;
		}

		s++;
		if (*s == 'l') {
			along = 1;
			s++;
			if (*s == 'l')
				s++;
		}

		switch (*s) {
		case 's':
			print_string(va_arg(args, char *), &b);
			break;
		case 'd':
			if (along)
				print_num_l(va_arg(args, long), &b);
			else
				print_num(va_arg(args, int), &b);
			break;
		case 'x':
			if (along)
				print_hex_l(va_arg(args, long), &b);
			else
				print_hex(va_arg(args, unsigned int), &b);
			break;
		}
		s++;
	}
	va_end(args);

	sbuf_flush(&b);
}
