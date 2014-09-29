#ifndef __CR_BFD_H__
#define __CR_BFD_H__
struct bfd_buf;
struct xbuf {
	char *mem;		/* buffer */
	char *data;		/* position we see bytes at */
	unsigned int sz;	/* bytes sitting after b->pos */
	struct bfd_buf *buf;
};

struct bfd {
	int fd;
	struct xbuf b;
};

#define BREADERR	((char *)-1)
int bfdopen(struct bfd *f);
void bclose(struct bfd *f);
char *breadline(struct bfd *f);
#endif
