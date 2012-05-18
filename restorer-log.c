#include "restorer-log.h"
#include "syscall.h"

static int logfd;

void restorer_set_logfd(int fd)
{
	logfd = fd;
}

#define add_ord(c)			\
	do {				\
		if (c < 10)		\
			c += '0';	\
		else			\
			c += 'a' - 10;	\
	} while (0)

void write_string(char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(logfd, str, len);
}

void write_string_n(char *str)
{
	char new_line = '\n';

	write_string(str);
	sys_write(logfd, &new_line, 1);
}

void write_num(long num)
{
	unsigned long d = 1000000000000000000;
	unsigned int started = 0;
	unsigned int c;

	if (num < 0) {
		num = -num;
		c = '-';
		sys_write(logfd, &c, 1);
	}

	while (d) {
		c = num / d;
		num -= d * c;
		d /= 10;
		if (!c && !started)
			continue;
		if (!started)
			started = 1;
		add_ord(c);
		sys_write(logfd, &c, 1);

	}
}

void write_num_n(long num)
{
	unsigned char c;
	write_num(num);
	c = '\n';
	sys_write(logfd, &c, sizeof(c));
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
		add_ord(c);
		buf[i++] = c;

	}

	buf[i++] = 0;

	return i;
}

void write_hex_n(unsigned long num)
{
	unsigned char *s = (unsigned char *)&num;
	unsigned char c;
	int i;

	c = 'x';
	sys_write(logfd, &c, 1);
	for (i = sizeof(long)/sizeof(char) - 1; i >= 0; i--) {
		c = (s[i] & 0xf0) >> 4;
		add_ord(c);
		sys_write(logfd, &c, 1);

		c = (s[i] & 0x0f);
		add_ord(c);
		sys_write(logfd, &c, 1);
	}

	c = '\n';
	sys_write(logfd, &c, 1);
}
