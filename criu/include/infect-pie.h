#ifndef __CR_INFECT_PIE_H__
#define __CR_INFECT_PIE_H__
extern int parasite_daemon_cmd(int cmd, void *args);
extern int parasite_trap_cmd(int cmd, void *args);
extern void parasite_cleanup(void);
extern int parasite_get_rpc_sock(void);
#endif
