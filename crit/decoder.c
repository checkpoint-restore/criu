#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

typedef struct {
	unsigned int	magic;
	unsigned int	size;
	unsigned int	nargs;
	unsigned int	mask;
	long		fmt;
	long		args[0];
} flog_msg_t;

#define MAGIC 0xABCDABCD

#define BUF_SIZE (1<<20)
static char _mbuf[BUF_SIZE];
static char *mbuf = _mbuf;
static char *fbuf;
static uint64_t fsize;
static uint64_t mbuf_size = sizeof(_mbuf);

#define LOG_BUF_LEN		(8*1024)
static char buffer[LOG_BUF_LEN];
static char buf_off = 0;

int decode_all(int fdin, int fdout)
{
	flog_msg_t *m = (void *)mbuf;
	void *values[34];
	size_t i, ret;
	char *fmt;
	int size, n;

	while (1) {
		ret = read(fdin, mbuf, sizeof(m));

		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}
		if (m->magic != MAGIC) {
			fprintf(stderr, "The log file was not properly closed\n");
			break;
		}
		ret = m->size - sizeof(m);
		if (m->size > mbuf_size) {
			fprintf(stderr, "The buffer is too small");
			return -1;
		}
		if (read(fdin, mbuf + sizeof(m), ret) != ret) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}

		fmt = mbuf + m->fmt;
		values[0] = &fmt;

		for (i = 0; i < m->nargs; i++) {
			values[i + 1] = (void *)&m->args[i];
			if (m->mask & (1u << i)) {
				m->args[i] = (long)(mbuf + m->args[i]);
			}
		}

		size  = vsnprintf(buffer + buf_off, sizeof buffer - buf_off, fmt, (void *)values);
		size += buf_off;
		ret = write(fdout, buffer, size );
	}
	return 0;
}

int main(int argc, char *argv[]){
	int fdin, fdout;
	fdin = open(argv[1], O_RDONLY);
	fdout = open(argv[2], O_CREAT|O_TRUNC|O_WRONLY|O_APPEND);
	decode_all(fdin, fdout);
}
