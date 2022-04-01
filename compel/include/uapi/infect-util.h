#ifndef __COMPEL_INFECT_UTIL_H__
#define __COMPEL_INFECT_UTIL_H__

#include "common/compiler.h"

/*
 * compel_run_id is a unique value of the current run. It can be used to
 * generate resource ID-s to avoid conflicts with other processes.
 */
extern uint64_t compel_run_id;

struct parasite_ctl;
extern int __must_check compel_util_send_fd(struct parasite_ctl *ctl, int fd);
extern int compel_util_recv_fd(struct parasite_ctl *ctl, int *pfd);
#endif
