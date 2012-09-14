#include "restorer-log.h"
#include "syscall.h"

static int current_logfd;
static unsigned int current_loglevel;

#define __add_ord(c)			\
	do {				\
		if (c < 10)		\
			c += '0';	\
		else			\
			c += 'a' - 10;	\
	} while (0)

void restorer_set_logfd(int fd)
{
	current_logfd = fd;
}

void restorer_set_loglevel(unsigned int loglevel)
{
	current_loglevel = loglevel;
}

static void write_str(const char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(current_logfd, str, len);
}

void print_on_level(unsigned int loglevel, const char *str, ...)
{
	if (loglevel > current_loglevel)
		return;
	write_str(str);
}

void write_str_n_on_level(unsigned int loglevel, char *str)
{
	char new_line = '\n';

	if (loglevel > current_loglevel)
		return;

	write_str(str);
	sys_write(current_logfd, &new_line, 1);
}

static void write_num(long num)
{
	unsigned long d = 1000000000000000000;
	unsigned int started = 0;
	unsigned int c;

	if (num < 0) {
		num = -num;
		c = '-';
		sys_write(current_logfd, &c, 1);
	}

	while (d) {
		c = num / d;
		num -= d * c;
		d /= 10;
		if (!c && !started)
			continue;
		if (!started)
			started = 1;
		__add_ord(c);
		sys_write(current_logfd, &c, 1);

	}
}

void write_num_on_level(unsigned int loglevel, long num)
{
	if (loglevel > current_loglevel)
		return;
	write_num(num);
}

void write_num_n_on_level(unsigned int loglevel, long num)
{
	unsigned char c = '\n';

	if (loglevel > current_loglevel)
		return;

	write_num(num);
	sys_write(current_logfd, &c, sizeof(c));
}

void write_hex_n_on_level(unsigned int loglevel, unsigned long num)
{
	unsigned char *s = (unsigned char *)&num;
	unsigned char c;
	int i;

	if (loglevel > current_loglevel)
		return;

	c = 'x';
	sys_write(current_logfd, &c, 1);
	for (i = sizeof(long)/sizeof(char) - 1; i >= 0; i--) {
		c = (s[i] & 0xf0) >> 4;
		__add_ord(c);
		sys_write(current_logfd, &c, 1);

		c = (s[i] & 0x0f);
		__add_ord(c);
		sys_write(current_logfd, &c, 1);
	}

	c = '\n';
	sys_write(current_logfd, &c, 1);
}

long vprint_num(char *buf, long num)
{
	unsigned long d = 1000000000000000000;
	unsigned int started = 0;
	unsigned int i = 0;
	unsigned int c;

	if (num < 0) {
		num = -num;
		buf[i++] = '-';
	}

	while (d) {
		c = num / d;
		num -= d * c;
		d /= 10;
		if (!c && !started)
			continue;
		if (!started)
			started = 1;
		__add_ord(c);
		buf[i++] = c;

	}

	buf[i++] = 0;

	return i;
}
