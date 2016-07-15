#ifndef __CR_FILES_REG_H__
#define __CR_FILES_REG_H__

#include "asm/types.h"
#include "files.h"

#include "images/regfile.pb-c.h"
#include "images/ghost-file.pb-c.h"

struct cr_imgset;
struct fd_parms;

struct file_remap {
	char *rpath;
	bool is_dir;
	int  rmnt_id;
	unsigned int users;
	uid_t owner;
};

struct reg_file_info {
	struct file_desc	d;
	RegFileEntry		*rfe;
	struct file_remap	*remap;
	bool			size_mode_checked;
	bool			is_dir;
	char			*path;
};

extern int open_reg_by_id(u32 id);
extern int open_reg_fd(struct file_desc *);
extern int open_path(struct file_desc *, int (*open_cb)(int ns_root_fd,
			struct reg_file_info *, void *), void *arg);
extern void clear_ghost_files(void);

extern int prepare_shared_reg_files(void);

extern const struct fdtype_ops regfile_dump_ops;
extern int do_open_reg_noseek_flags(int ns_root_fd, struct reg_file_info *rfi, void *arg);
extern int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p);

extern struct file_remap *lookup_ghost_remap(u32 dev, u32 ino);
extern void remap_put(struct file_remap *remap);

extern struct file_desc *try_collect_special_file(u32 id, int optional);
#define collect_special_file(id)	try_collect_special_file(id, 0)
extern int collect_filemap(struct vma_area *);

extern int collect_remaps_and_regfiles(void);

extern void delete_link_remaps(void);
extern void free_link_remaps(void);
extern int prepare_remaps(void);
extern void try_clean_remaps(void);

extern int strip_deleted(struct fd_link *link);

extern int prepare_procfs_remaps(void);
extern int dead_pid_conflict(void);

#endif /* __CR_FILES_REG_H__ */
