#ifndef __CR_BFD_H__
#define __CR_BFD_H__

#include "common/err.h"

struct iovec;
struct rb_buffer;
struct bfd {
    int fd;
    bool writable;
    struct rb_buffer *rb_data;
};

static inline bool bfd_buffered(struct bfd *b)
{
	return b->rb_data != NULL;
}

static inline void bfd_setraw(struct bfd *b)
{
	b->rb_data = NULL;
}

int bfdopenr(struct bfd *f);
int bfdopenw(struct bfd *f);
void bclose(struct bfd *f);
char *breadline(struct bfd *f);
char *breadchr(struct bfd *f, char c);
int bwrite(struct bfd *f, const void *buf, int sz);
struct iovec;
int bwritev(struct bfd *f, const struct iovec *iov, int cnt);
int bread(struct bfd *f, void *buf, int sz);
int bfd_flush_images(void);
#endif
