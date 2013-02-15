#ifndef __CR_FILE_IDS_H__
#define __CR_FILE_IDS_H__

#include "compiler.h"
#include "asm/types.h"
#include "rbtree.h"

#include "protobuf/fdinfo.pb-c.h"

#define FD_PID_INVALID		(-2U)
#define FD_DESC_INVALID		(-3U)

struct fdinfo_entry;
extern int fd_id_generate(pid_t pid, FdinfoEntry *fe);
extern u32 fd_id_generate_special(void);
extern void fd_id_show_tree(void);

#endif /* __CR_FILE_IDS_H__ */
