#ifndef __CR_SIGNALFD_H__
#define __CR_SIGNALFD_H__

struct cr_fdset;
struct fd_parms;
extern int is_signalfd_link(int lfd);
extern const struct fdtype_ops signalfd_dump_ops;
extern struct collect_image_info signalfd_cinfo;

#endif /* __CR_SIGNALFD_H__ */
