#ifndef __CR_SECURITY_H__
#define __CR_SECURITY_H__

#include "proc_parse.h"
#include "protobuf/creds.pb-c.h"

extern int restrict_uid(unsigned int uid, unsigned int gid);
extern bool may_dump(struct proc_status_creds *);
extern bool may_restore(struct _CredsEntry *);
extern bool cr_user_is_root(void);
extern int cr_fchown(int fd);

#endif /* __CR_SECURITY_H__ */
