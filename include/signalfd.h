#ifndef __CR_SIGNALFD_H__
#define __CR_SIGNALFD_H__

struct cr_fdset;
struct fd_parms;
struct cr_options;
extern int is_signalfd_link(int lfd);
extern int dump_signalfd(struct fd_parms *p, int lfd, const int fdinfo);
extern void show_signalfd(int fd, struct cr_options *o);
extern int collect_signalfd(void);

#endif /* __CR_SIGNALFD_H__ */
