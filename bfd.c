#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "log.h"
#include "bfd.h"
#include "list.h"
#include "xmalloc.h"
#include "asm-generic/page.h"

/*
 * Kernel doesn't produce more than one page of
 * date per one read call on proc files.
 */
#define BUFSIZE	(PAGE_SIZE)

struct bfd_buf {
	char *mem;
	struct list_head l;
};

static LIST_HEAD(bufs);

#define BUFBATCH	(16)

static int buf_get(struct xbuf *xb)
{
	struct bfd_buf *b;

	if (list_empty(&bufs)) {
		void *mem;
		int i;

		pr_debug("BUF++\n");
		mem = mmap(NULL, BUFBATCH * BUFSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, 0, 0);
		if (mem == MAP_FAILED) {
			pr_perror("bfd: No buf");
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

			b->mem = mem + i * BUFSIZE;
			list_add_tail(&b->l, &bufs);
		}
	}

	b = list_first_entry(&bufs, struct bfd_buf, l);
	list_del_init(&b->l);

	xb->mem = b->mem;
	xb->data = xb->mem;
	xb->sz = 0;
	xb->buf = b;
	pr_debug("BUF %p <\n", xb->mem);
	return 0;
}

static void buf_put(struct xbuf *xb)
{
	/*
	 * Don't unmap buffer back, it will get reused
	 * by next bfdopen call
	 */
	pr_debug("BUF %p >\n", xb->mem);
	list_add(&xb->buf->l, &bufs);
	xb->buf = NULL;
	xb->mem = NULL;
	xb->data = NULL;
}

int bfdopen(struct bfd *f)
{
	if (buf_get(&f->b)) {
		close(f->fd);
		return -1;
	}

	return 0;
}

void bclose(struct bfd *f)
{
	if (bfd_buffered(f))
		buf_put(&f->b);
	close(f->fd);
}

static int brefill(struct bfd *f)
{
	int ret;
	struct xbuf *b = &f->b;

	memmove(b->mem, b->data, b->sz);
	b->data = b->mem;

	ret = read(f->fd, b->mem + b->sz, BUFSIZE - b->sz);
	if (ret < 0) {
		pr_perror("bfd: Error reading file");
		return -1;
	}

	if (ret == 0)
		return 0;

	b->sz += ret;
	return 0;
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
	struct xbuf *b = &f->b;
	bool refilled = false;
	char *n;
	unsigned int ss = 0;

again:
	n = strnchr(b->data + ss, b->sz - ss, '\n');
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

	/*
	 * small optimization -- we've scanned b->sz
	 * symols already, no need to re-scan them after
	 * the buffer refill.
	 */
	ss = b->sz;

	/* no full line in the buffer -- refill one */
	if (brefill(f))
		return BREADERR;

	refilled = true;

	goto again;
}

int bwrite(struct bfd *bfd, const void *buf, int size)
{
	return write(bfd->fd, buf, size);
}

int bwritev(struct bfd *bfd, const struct iovec *iov, int cnt)
{
	return writev(bfd->fd, iov, cnt);
}

int bread(struct bfd *bfd, void *buf, int size)
{
	return read(bfd->fd, buf, size);
}
