#ifndef __CR_AUTOFS_H__
#define __CR_AUTOFS_H__

#ifndef AUTOFS_MINOR
#define AUTOFS_MINOR	235
#endif

bool is_autofs_pipe(unsigned long inode);

struct mount_info;
int autofs_parse(struct mount_info *pm);

#endif
