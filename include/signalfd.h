#ifndef __CR_SIGNALFD_H__
#define __CR_SIGNALFD_H__

struct cr_fdset;
struct fd_parms;
extern int is_signalfd_link(int lfd);
extern const struct fdtype_ops signalfd_dump_ops;
extern void show_signalfd(int fd);
extern int collect_signalfd(void);

#endif /* __CR_SIGNALFD_H__ */
