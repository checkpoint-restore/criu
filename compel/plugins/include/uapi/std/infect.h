#ifndef COMPEL_PLUGIN_STD_INFECT_H__
#define COMPEL_PLUGIN_STD_INFECT_H__

#include "common/compiler.h"

extern int parasite_get_rpc_sock(void);
extern int __must_check parasite_service(unsigned int cmd, void *args);

/*
 * Must be supplied by user plugins.
 */
extern int __must_check parasite_daemon_cmd(int cmd, void *args);
extern int __must_check parasite_trap_cmd(int cmd, void *args);
extern void parasite_cleanup(void);

/*
 * FIXME: Should be supplied by log module.
 */
extern void log_set_fd(int fd);
extern void log_set_loglevel(unsigned int level);

#endif /* COMPEL_PLUGIN_STD_INFECT_H__ */
