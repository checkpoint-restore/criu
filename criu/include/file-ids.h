#ifndef __CR_FILE_IDS_H__
#define __CR_FILE_IDS_H__

#include "common/compiler.h"
#include "rbtree.h"

#include "images/fdinfo.pb-c.h"

#define FD_PID_INVALID	(-2U)
#define FD_DESC_INVALID (-3U)

struct fdinfo_entry;
struct stat;

struct fd_parms;
extern int fd_id_generate(pid_t pid, FdinfoEntry *fe, struct fd_parms *p);
extern int fd_id_generate_special(struct fd_parms *p, u32 *id);

extern struct kid_tree fd_tree;

#endif /* __CR_FILE_IDS_H__ */
