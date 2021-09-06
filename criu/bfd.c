#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>

#include "int.h"
#include "log.h"
#include "common/bug.h"
#include "bfd.h"
#include "common/list.h"
#include "util.h"
#include "xmalloc.h"
#include "page.h"

#undef LOG_PREFIX
#define LOG_PREFIX "bfd: "

/* multiple files can have the same name without any side effects */
#define RB_NAME "/tmp/rb_criu"

/*
 * Kernel doesn't produce more than one page of
 * date per one read call on proc files.
 */
#define BUFSIZE (PAGE_SIZE)

struct bfd_buf {
	char *mem;
	struct list_head l;
};

static LIST_HEAD(bufs);

#define BUFBATCH (16)

/* lockless ring buufer releated */
#define rb_read_address(rb) (rb->mem + rb->read)
#define rb_write_address(rb) (rb->mem + rb->write)
#define rb_useful_bytes(rb) ((rb->write - rb->read + rb->size) & (rb->size - 1))
#define rb_free_bytes(rb) (rb->size - rb_useful_bytes(rb) - 1)

/* rb->size should be exp of 2 */
static inline void rb_write_advance(struct xbuf *rb, unsigned long counts)
{
	rb->write = (rb->write + counts) & (rb->size - 1);
}

static inline void rb_read_advance(struct xbuf *rb, unsigned long counts)
{
	rb->read = (rb->read + counts) & (rb->size - 1);
}

static int buf_get(struct xbuf *xb)
{
	struct bfd_buf *b;

	if (list_empty(&bufs)) {
		void *mem;
		int i, memfd, ret;

		memfd = memfd_create(RB_NAME, 0);
		if (memfd == -1) {
			pr_err("Create temp file from memory failed\n");
			return -1;
		}

		ret = ftruncate(memfd, BUFBATCH * BUFSIZE);
		if (ret == -1) {
			pr_err("Ftruncate file failed\n");
			return -1;
		}

		for (i = 0; i < BUFBATCH; i++) {
			b = xmalloc(sizeof(*b));
			if (!b) {
				if (i == 0) {
					pr_err("No buffer for bfd\n");
					return -1;
				}

				pr_warn("BFD buffers partial refil!\n");
				break;
			}

			b->mem = mmap(NULL, BUFSIZE << 1, PROT_NONE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			if (b->mem == MAP_FAILED) {
				pr_err("Mmap failed\n");
				return -1;
			}

			mem = mmap(b->mem, BUFSIZE, PROT_READ | PROT_WRITE,
				MAP_FIXED | MAP_SHARED, memfd, i * BUFSIZE);
			if (mem != b->mem) {
				pr_err("Mmap fixed failed\n");
				return -1;
			}

			mem = mmap(b->mem + BUFSIZE, BUFSIZE, PROT_READ | PROT_WRITE,
				MAP_FIXED | MAP_SHARED, memfd, i * BUFSIZE);
			if (mem != b->mem + BUFSIZE) {
				pr_err("Mmap fixed failed\n");
				return -1;
			}

			list_add_tail(&b->l, &bufs);
		}
		close(memfd);
	}

	b = list_first_entry(&bufs, struct bfd_buf, l);
	list_del_init(&b->l);

	xb->mem = b->mem;
	xb->read = xb->write = 0;
	xb->size = BUFSIZE;
	xb->buf = b;
	return 0;
}

static void buf_put(struct xbuf *xb)
{
	/*
	 * Don't unmap buffer back, it will get reused
	 * by next bfdopen call
	 */
	list_add(&xb->buf->l, &bufs);
	xb->buf = NULL;
	xb->mem = NULL;
	xb->size = 0;
}

static int bfdopen(struct bfd *f, bool writable)
{
	if (buf_get(&f->b)) {
		close_safe(&f->fd);
		return -1;
	}

	f->writable = writable;
	return 0;
}

int bfdopenr(struct bfd *f)
{
	return bfdopen(f, false);
}

int bfdopenw(struct bfd *f)
{
	return bfdopen(f, true);
}

static int bflush(struct bfd *bfd);
static bool flush_failed = false;

int bfd_flush_images(void)
{
	return flush_failed ? -1 : 0;
}

void bclose(struct bfd *f)
{
	if (bfd_buffered(f)) {
		if (f->writable && bflush(f) < 0) {
			/*
			 * This is to propagate error up. It's
			 * hardly possible by returning and
			 * checking it, but setting a static
			 * flag, failing further bfdopen-s and
			 * checking one at the end would work.
			 */
			flush_failed = true;
			pr_perror("Error flushing image");
		}

		buf_put(&f->b);
	}
	close_safe(&f->fd);
}

static int brefill(struct bfd *f)
{
	int ret;
	struct xbuf *rb = &f->b;
	char *write_addr = rb_write_address(rb);
	unsigned long free_size = rb_free_bytes(rb);

	ret = read_all(f->fd, write_addr, free_size);
	if (ret < 0) {
		pr_perror("Error reading file");
		return -1;
	}

	rb_write_advance(rb, ret);
	return ret;
}

static char *strnchr(char *str, unsigned int len, char c)
{
	while (len > 0 && *str != c) {
		str++;
		len--;
	}

	return len == 0 ? NULL : str;
}

char *breadline(struct bfd *f)
{
	return breadchr(f, '\n');
}

char *breadchr(struct bfd *f, char c)
{
	struct xbuf *rb = &f->b;
	bool refilled = false;
	char *n;
	unsigned int ss = 0;
	unsigned long useful_size;
	char *read_addr;

	read_addr = rb_read_address(rb);

again:
	useful_size = rb_useful_bytes(rb);
	n = strnchr(read_addr + ss, useful_size - ss, c);
	if (n) {
		*n = '\0';
		rb_read_advance(rb, (n + 1 - read_addr));
		return read_addr;
	}

	if (refilled) {
		if (!useful_size)
			return NULL;

		if (useful_size == BUFSIZE) {
			pr_err("The bfd buffer is too small\n");
			return ERR_PTR(-EIO);
		}
		/*
		 * Last bytes may lack the \n at the
		 * end, need to report this as full
		 * line anyway
		 */
		read_addr[useful_size] = '\0';

		/*
		 * The b->data still points to old data,
		 * but we say that no bytes left there
		 * so next call to breadline will not
		 * "find" these bytes again.
		 */
		rb_read_advance(rb, useful_size);
		return read_addr;
	}

	/*
	 * small optimization -- we've scanned b->sz
	 * symbols already, no need to re-scan them after
	 * the buffer refill.
	 */
	ss = useful_size;

	/* no full line in the buffer -- refill one */
	if (brefill(f) < 0)
		return ERR_PTR(-EIO);

	refilled = true;

	goto again;
}

static int bflush(struct bfd *bfd)
{
	struct xbuf *rb = &bfd->b;
	unsigned long useful_size = rb_useful_bytes(rb);
	char *read_addr = rb_read_address(rb);
	int ret;

	if (!useful_size)
		return 0;

	ret = write_all(bfd->fd, read_addr, useful_size);
	if (ret != useful_size)
		return -1;

	rb_read_advance(rb, useful_size);
	return 0;
}

static int __bwrite(struct bfd *bfd, const void *buf, int size)
{
	struct xbuf *rb = &bfd->b;

	if (size > rb_free_bytes(rb)) {
		int ret;
		ret = bflush(bfd);
		if (ret < 0)
			return ret;
	}

	/* after flush, free bytes should be size - 1 */
	if (size >= rb->size)
		return write_all(bfd->fd, buf, size);

	memcpy(rb_write_address(rb), buf, size);
	rb_write_advance(rb, size);
	return size;
}

int bwrite(struct bfd *bfd, const void *buf, int size)
{
	if (!bfd_buffered(bfd))
		return write_all(bfd->fd, buf, size);

	return __bwrite(bfd, buf, size);
}

int bwritev(struct bfd *bfd, const struct iovec *iov, int cnt)
{
	int i, written = 0;

	if (!bfd_buffered(bfd)) {
		/*
		 * FIXME writev() should be called again if writev() writes
		 * less bytes than requested.
		 */
		return writev(bfd->fd, iov, cnt);
	}

	for (i = 0; i < cnt; i++) {
		int ret;

		ret = __bwrite(bfd, (const void *)iov[i].iov_base, iov[i].iov_len);
		if (ret < 0)
			return ret;

		written += ret;
		if (ret < iov[i].iov_len)
			break;
	}

	return written;
}

int bread(struct bfd *bfd, void *buf, int size)
{
	struct xbuf *rb = &bfd->b;
	int more = 1, filled = 0;
	char *read_addr = rb_read_address(rb);
	unsigned long useful_bytes = rb_useful_bytes(rb);

	if (!bfd_buffered(bfd))
		return read_all(bfd->fd, buf, size);

	while (more > 0) {
		int chunk;

		chunk = size - filled;
		if (chunk > useful_bytes)
			chunk = useful_bytes;

		if (chunk) {
			memcpy(buf + filled, read_addr, chunk);
			rb_read_advance(rb, chunk);
			filled += chunk;
		}

		if (filled < size)
			more = brefill(bfd);
		else {
			BUG_ON(filled > size);
			more = 0;
		}

		read_addr = rb_read_address(rb);
		useful_bytes = rb_useful_bytes(rb);
	}

	return more < 0 ? more : filled;
}
