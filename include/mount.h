#ifndef MOUNT_H__
#define MOUNT_H__

struct proc_mountinfo;

extern int open_mount(unsigned int s_dev);
extern int collect_mount_info(void);

struct cr_fdset;
extern int dump_mnt_ns(int pid, struct cr_fdset *);
struct cr_options;
extern void show_mountpoints(int fd, struct cr_options *);
int prepare_mnt_ns(int pid);

#endif /* MOUNT_H__ */
