#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>

#include "list.h"
#include "asm/types.h"
#include "servicefd.h"

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern int check_img_inventory(void);
extern int write_img_inventory(void);
extern void kill_inventory(void);

#define LAST_PID_PATH		"sys/kernel/ns_last_pid"

extern int cr_dump_tasks(pid_t pid);
extern int cr_pre_dump_tasks(pid_t pid);
extern int cr_restore_tasks(void);
extern int cr_show(int pid);
extern int convert_to_elf(char *elf_path, int fd_core);
extern int cr_check(void);
extern int cr_exec(int pid, char **opts);
extern int cr_dedup(void);

extern int check_add_feature(char *arg);

#endif /* __CR_CRTOOLS_H__ */
