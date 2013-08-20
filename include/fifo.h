#ifndef __CR_FIFO_H__
#define __CR_FIFO_H__

struct fd_parms;
struct cr_fdset;

extern const struct fdtype_ops fifo_dump_ops;
extern struct collect_image_info fifo_cinfo;
extern int collect_fifo(void);

#endif /* __CR_FIFO_H__ */
