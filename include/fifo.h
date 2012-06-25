#ifndef FIFO_H__
#define FIFO_H__

struct fd_parms;
struct cr_fdset;

extern int dump_fifo(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int collect_fifo(void);

#endif /* FIFO_H__ */
