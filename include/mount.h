#ifndef MOUNT_H__
#define MOUNT_H__

struct proc_mountinfo;

extern int open_mnt_root(unsigned int s_dev, struct proc_mountinfo *mntinfo, int nr_mntinfo);

#endif /* MOUNT_H__ */
