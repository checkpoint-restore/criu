#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#ifdef CONFIG_HAS_FLOG
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
	void *values[34], *b[2];
	size_t i, ret;
	char *fmt;
	off_t r;
	int size, n;

	while (1) {
		ret = read(fdin, mbuf, sizeof(m));

		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Unable to read a message: %m\n");
			return -1;
		}
		if (m->magic != MAGIC) {
			r = lseek(fdin, -sizeof(ret), SEEK_CUR);
			if(r == (off_t) -1){
				fprintf(stderr, "Error while seeking file: %m\n");
				return -1;
			}
			i = read(fdin, b, 1);
			if(i == -1){
				fprintf(stderr, "Error while reading file: %m\n");
				return -1;
			}
			i = write(fdout, b, 1);
			if(i == -1){
				fprintf(stderr, "Error while writing to file: %m\n");
				return -1;
			}
			continue;
		}
		ret = m->size - sizeof(m);
		if (m->size > mbuf_size) {
			fprintf(stderr, "The buffer is too small\n");
			return -1;
		}
		if (read(fdin, mbuf + sizeof(m), ret) != ret) {
			fprintf(stderr, "Unable to read a message: %m\n");
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
		ret = write(fdout, buffer, size);
	}
	return 0;
}

int main(int argc, char *argv[]){
	int fdin, fdout;
	fdin = open(argv[1], O_RDONLY);
	if (fdin<0){
		fprintf(stderr, "Unable to open file: %m\n");
		return -1;
	}
	fdout = open(argv[2], O_CREAT|O_TRUNC|O_WRONLY|O_APPEND);
	if (fdout<0){
		fprintf(stderr, "Unable to open file: %m\n");
		return -1;
	}
	return decode_all(fdin, fdout);
}

#else
#define BUF_SIZE (1<<20)

int main(int argc, char *argv[]){
	int fdin, fdout;
	ssize_t ret;
	static char _mbuf[BUF_SIZE];
	static char *buf = _mbuf;

	fdin = open(argv[1], O_RDONLY);
	if (fdin<0){
		fprintf(stderr, "Unable to open file: %m\n");
		return -1;
	}
	fdout = open(argv[2], O_CREAT|O_TRUNC|O_WRONLY|O_APPEND);
	if (fdout<0){
		fprintf(stderr, "Unable to open file: %m\n");
		return -1;
	}
	ret = read(fdin, buf, sizeof(buf));
	while (ret)
	{
		write(fdout, buf, sizeof(buf));
		ret = read(fdin, buf, sizeof(buf));
	}
	return 0;
}

#endif /*CONFIG_HAS_FLOG*/
