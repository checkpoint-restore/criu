#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>

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

/*
 * Kernel doesn't produce more than one page of
 * date per one read call on proc files.
 */
#define BUFSIZE (PAGE_SIZE)

#define BFD_MAX_DYNAMIC_SIZE (2 * 1024 * 1024)

struct bfd_buf {
	char *mem;
	struct list_head l;
};

static LIST_HEAD(bufs);
static pthread_mutex_t bufs_lock = PTHREAD_MUTEX_INITIALIZER;

#define BUFBATCH (16)

static int buf_get(struct xbuf *xb)
{
	struct bfd_buf *b;

	pthread_mutex_lock(&bufs_lock);

	if (list_empty(&bufs)) {
		void *mem;
		int i;

		mem = mmap(NULL, BUFBATCH * BUFSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (mem == MAP_FAILED) {
			pthread_mutex_unlock(&bufs_lock);
			pr_perror("No buf");
			return -1;
		}

		for (i = 0; i < BUFBATCH; i++) {
			b = xmalloc(sizeof(*b));
			if (!b) {
				if (i == 0) {
					pthread_mutex_unlock(&bufs_lock);
					pr_err("No buffer for bfd\n");
					return -1;
				}

				pr_warn("BFD buffers partial refil!\n");
				break;
			}

			b->mem = mem + i * BUFSIZE;
			list_add_tail(&b->l, &bufs);
		}
	}

	b = list_first_entry(&bufs, struct bfd_buf, l);
	list_del_init(&b->l);

	xb->mem = b->mem;
	xb->data = xb->mem;
	xb->bsize = BUFSIZE;
	xb->sz = 0;
	xb->buf = b;
	pthread_mutex_unlock(&bufs_lock);
	return 0;
}

static void buf_put(struct xbuf *xb)
{
	if (xb->buf) {
		/*
		 * Don't unmap standard buffer back, it will get reused
		 * by next bfdopen call
		 */
		pthread_mutex_lock(&bufs_lock);
		list_add(&xb->buf->l, &bufs);
		pthread_mutex_unlock(&bufs_lock);
	} else {
		/* This buffer was dynamically extended, unmap it */
		munmap(xb->mem, xb->bsize);
	}
	xb->buf = NULL;
	xb->mem = NULL;
	xb->data = NULL;
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

int bfd_flush(struct bfd *f)
{
	if (!bfd_buffered(f))
		return 0;

	if (!f->writable)
		return 0;

	return bflush(f);
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
	struct xbuf *b = &f->b;

	memmove(b->mem, b->data, b->sz);
	b->data = b->mem;

	ret = read_all(f->fd, b->mem + b->sz, b->bsize - b->sz);
	if (ret < 0) {
		pr_perror("Error reading file");
		return -1;
	}

	if (ret == 0)
		return 0;

	b->sz += ret;
	return 1;
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

static int bextend(struct bfd *f)
{
	struct xbuf *b = &f->b;
	void *newbuf;
	long newsize = b->bsize * 2;

	if (newsize > BFD_MAX_DYNAMIC_SIZE) {
		pr_err("Line too long to fit in BFD_MAX_DYNAMIC_SIZE\n");
		return -1;
	}

	if (b->buf) {
		newbuf = mmap(NULL, newsize, PROT_READ | PROT_WRITE,
					     MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (newbuf == MAP_FAILED) {
			pr_perror("Error allocating buffer");
			return -1;
		}
		memcpy(newbuf, b->mem, b->sz);
		pthread_mutex_lock(&bufs_lock);
		list_add(&b->buf->l, &bufs);
		pthread_mutex_unlock(&bufs_lock);
		b->buf = NULL;
	} else {
		newbuf = mremap(b->mem, b->bsize, newsize, MREMAP_MAYMOVE);
		if (newbuf == MAP_FAILED) {
			pr_perror("Error allocating buffer");
			return -1;
		}
	}
	b->mem = newbuf;
	b->data = newbuf;
	b->bsize = newsize;
	return 0;
}

char *breadchr(struct bfd *f, char c)
{
	struct xbuf *b = &f->b;
	bool refilled = false;
	char *n;
	unsigned int ss = 0;

again:
	n = strnchr(b->data + ss, b->sz - ss, c);
	if (n) {
		char *ret;

		ret = b->data;
		b->data = n + 1; /* skip the \n found */
		*n = '\0';
		b->sz -= (b->data - ret);
		return ret;
	}

	if (refilled) {
		if (!b->sz)
			return NULL;

		if (b->sz == b->bsize) {
			if (bextend(f)) {
				pr_err("The bfd buffer is too small\n");
				return ERR_PTR(-EIO);
			}
			goto refill;
		}
		/*
		 * Last bytes may lack the \n at the
		 * end, need to report this as full
		 * line anyway
		 */
		b->data[b->sz] = '\0';

		/*
		 * The b->data still points to old data,
		 * but we say that no bytes left there
		 * so next call to breadline will not
		 * "find" these bytes again.
		 */
		b->sz = 0;
		return b->data;
	}

refill:
	/*
	 * small optimization -- we've scanned b->sz
	 * symbols already, no need to re-scan them after
	 * the buffer refill.
	 */
	ss = b->sz;

	/* no full line in the buffer -- refill one */
	if (brefill(f) < 0)
		return ERR_PTR(-EIO);

	refilled = true;

	goto again;
}

static int bflush(struct bfd *bfd)
{
	struct xbuf *b = &bfd->b;
	int ret;

	if (!b->sz)
		return 0;

	ret = write_all(bfd->fd, b->data, b->sz);
	if (ret != b->sz)
		return -1;

	b->sz = 0;
	return 0;
}

static int __bwrite(struct bfd *bfd, const void *buf, int size)
{
	struct xbuf *b = &bfd->b;

	if (b->sz + size > b->bsize) {
		int ret;
		ret = bflush(bfd);
		if (ret < 0)
			return ret;
	}

	if (size > b->bsize)
		return write_all(bfd->fd, buf, size);

	memcpy(b->data + b->sz, buf, size);
	b->sz += size;
	return size;
}

int bwrite(struct bfd *bfd, const void *buf, int size)
{
	if (!bfd_buffered(bfd))
		return write_all(bfd->fd, buf, size);

	return __bwrite(bfd, buf, size);
}

int bwritev(struct bfd *bfd, struct iovec *iov, int cnt)
{
	int i, written = 0;

	if (!bfd_buffered(bfd)) {
		size_t off = 0;

		while (cnt) {
			ssize_t ret;

			/*
			 * Temporarily modify the first iovec to skip already-written
			 * bytes from previous partial writes, then restore it before
			 * the next iteration.
			 */
			iov[0].iov_base += off;
			iov[0].iov_len -= off;
			ret = writev(bfd->fd, iov, cnt);
			iov[0].iov_base -= off;
			iov[0].iov_len += off;
			if (ret < 0) {
				pr_perror("writev failed for fd %d", bfd->fd);
				return ret;
			}
			if (ret == 0) {
				errno = EIO;
				pr_perror("writev made no progress (fd %d)", bfd->fd);
				return -1;
			}

			written += ret;
			ret += off;
			while (ret) {
				if (iov[0].iov_len > ret) {
					off = ret;
					break;
				}
				ret -= iov[0].iov_len;
				iov++;
				cnt--;
				off = 0;
			}

		}
		return written;
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
	struct xbuf *b = &bfd->b;
	int more = 1, filled = 0;

	if (!bfd_buffered(bfd))
		return read_all(bfd->fd, buf, size);

	while (more > 0) {
		int chunk;

		chunk = size - filled;
		if (chunk > b->sz)
			chunk = b->sz;

		if (chunk) {
			memcpy(buf + filled, b->data, chunk);
			b->data += chunk;
			b->sz -= chunk;
			filled += chunk;
		}

		if (filled < size)
			more = brefill(bfd);
		else {
			BUG_ON(filled > size);
			more = 0;
		}
	}

	return more < 0 ? more : filled;
}
