#ifndef __CR_BFD_H__
#define __CR_BFD_H__

#include "err.h"

struct bfd_buf;
struct xbuf {
	char *mem;		/* buffer */
	char *data;		/* position we see bytes at */
	unsigned int sz;	/* bytes sitting after b->pos */
	struct bfd_buf *buf;
};

struct bfd {
	int fd;
	bool writable;
	struct xbuf b;
};

static inline bool bfd_buffered(struct bfd *b)
{
	return b->b.mem != NULL;
}

static inline void bfd_setraw(struct bfd *b)
{
	b->b.mem = NULL;
}

int bfdopenr(struct bfd *f);
int bfdopenw(struct bfd *f);
void bclose(struct bfd *f);
char *breadline(struct bfd *f);
int bwrite(struct bfd *f, const void *buf, int sz);
struct iovec;
int bwritev(struct bfd *f, const struct iovec *iov, int cnt);
int bread(struct bfd *f, void *buf, int sz);
int bfd_flush_images(void);
#endif
