#ifndef __COMPEL_INFECT_UTIL_H__
#define __COMPEL_INFECT_UTIL_H__

#include "common/compiler.h"

/**
 * The length of the hash is based on what libuuid provides.
 * According to the manpage this is:
 *
 * The uuid_unparse() function converts the supplied UUID uu from the binary
 * representation into a 36-byte string (plus trailing '\0')
 */
#define RUN_ID_HASH_LENGTH 37

/*
 * compel_run_id is a unique value of the current run. It can be used to
 * generate resource ID-s to avoid conflicts with other processes.
 */
extern char compel_run_id[RUN_ID_HASH_LENGTH];

struct parasite_ctl;
extern int __must_check compel_util_send_fd(struct parasite_ctl *ctl, int fd);
extern int compel_util_recv_fd(struct parasite_ctl *ctl, int *pfd);
#endif
