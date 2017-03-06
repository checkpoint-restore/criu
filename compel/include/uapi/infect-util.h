#ifndef __COMPEL_INFECT_UTIL_H__
#define __COMPEL_INFECT_UTIL_H__
struct parasite_ctl;
extern int compel_util_send_fd(struct parasite_ctl *ctl, int fd);
extern int compel_util_recv_fd(struct parasite_ctl *ctl, int *pfd);
#endif
