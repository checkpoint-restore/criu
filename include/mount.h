#ifndef __CR_MOUNT_H__
#define __CR_MOUNT_H__

extern int mntns_collect_root(pid_t pid);

struct proc_mountinfo;

extern int open_mount(unsigned int s_dev);
extern int collect_mount_info(pid_t pid);
extern struct fstype *find_fstype_by_name(char *fst);

struct cr_fdset;
struct ns_id;
extern struct mount_info * collect_mntinfo(struct ns_id *ns);
extern int dump_mnt_ns(struct ns_id *ns);
extern int prepare_mnt_ns(int pid);

extern int pivot_root(const char *new_root, const char *put_old);

struct mount_info;
extern struct mount_info *lookup_mnt_id(unsigned int id);
extern struct mount_info *lookup_mnt_sdev(unsigned int s_dev);

extern struct ns_desc mnt_ns_desc;

extern dev_t phys_stat_resolve_dev(dev_t st_dev, const char *path);
extern bool phys_stat_dev_match(dev_t st_dev, dev_t phys_dev, const char *path);

extern int restore_task_mnt_ns(struct ns_id *nsid, pid_t pid);
extern int fini_mnt_ns(void);

int rst_collect_local_mntns();
char *rst_get_mnt_root(int mnt_id);

#endif /* __CR_MOUNT_H__ */
