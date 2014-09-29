#ifndef __CR_BFD_H__
#define __CR_BFD_H__
struct bfd_buf;
struct xbuf {
	char *mem;		/* buffer */
	char *pos;		/* position we see bytes at */
	unsigned int bleft;	/* bytes left after b->pos */
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
