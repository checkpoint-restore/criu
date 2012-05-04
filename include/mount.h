#ifndef MOUNT_H__
#define MOUNT_H__

struct proc_mountinfo;

extern int open_mount(unsigned int s_dev);
extern int collect_mount_info(void);

#endif /* MOUNT_H__ */
