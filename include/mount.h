#ifndef __CR_MOUNT_H__
#define __CR_MOUNT_H__

extern struct mount_info *mntinfo;

struct ns_id;
extern int __mntns_get_root_fd(pid_t pid);
extern int mntns_get_root_fd(struct ns_id *ns);
extern struct ns_id *lookup_nsid_by_mnt_id(int mnt_id);

struct proc_mountinfo;

extern int open_mount(unsigned int s_dev);
extern struct fstype *find_fstype_by_name(char *fst);

struct cr_fdset;
extern struct mount_info * collect_mntinfo(struct ns_id *ns);
extern int prepare_mnt_ns(void);

extern int pivot_root(const char *new_root, const char *put_old);

struct mount_info;
extern struct mount_info *lookup_mnt_id(unsigned int id);
extern struct mount_info *lookup_mnt_sdev(unsigned int s_dev);

extern struct ns_desc mnt_ns_desc;

extern dev_t phys_stat_resolve_dev(struct mount_info *tree,
					dev_t st_dev, const char *path);
extern bool phys_stat_dev_match(struct mount_info *tree, dev_t st_dev,
					dev_t phys_dev, const char *path);

struct pstree_item;
extern int restore_task_mnt_ns(struct pstree_item *);
extern int fini_mnt_ns(void);

char *rst_get_mnt_root(int mnt_id);
int ext_mount_add(char *key, char *val);

#endif /* __CR_MOUNT_H__ */
