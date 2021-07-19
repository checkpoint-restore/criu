#ifndef __CR_FILES_REG_H__
#define __CR_FILES_REG_H__

#include "files.h"
#include "util.h"

#include "images/regfile.pb-c.h"
#include "images/ghost-file.pb-c.h"

struct cr_imgset;
struct fd_parms;

struct file_remap {
	char *rpath;
	bool is_dir;
	int rmnt_id;
	uid_t uid;
	gid_t gid;
};

struct reg_file_info {
	struct file_desc d;
	RegFileEntry *rfe;
	struct file_remap *remap;
	bool size_mode_checked;
	bool is_dir;
	char *path;
};

extern int open_reg_by_id(u32 id);
extern int open_reg_fd(struct file_desc *);
extern int open_path(struct file_desc *, int (*open_cb)(int ns_root_fd, struct reg_file_info *, void *), void *arg);

extern const struct fdtype_ops regfile_dump_ops;
extern int do_open_reg_noseek_flags(int ns_root_fd, struct reg_file_info *rfi, void *arg);
extern int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p);

extern struct file_remap *lookup_ghost_remap(u32 dev, u32 ino);

extern struct file_desc *try_collect_special_file(u32 id, int optional);
#define collect_special_file(id) try_collect_special_file(id, 0)
extern int collect_filemap(struct vma_area *);
extern void filemap_ctx_init(bool auto_close);
extern void filemap_ctx_fini(void);

extern struct collect_image_info reg_file_cinfo;
extern int collect_remaps_and_regfiles(void);

extern void delete_link_remaps(void);
extern void free_link_remaps(void);
extern int prepare_remaps(void);
extern int try_clean_remaps(bool only_ghosts);

static inline int link_strip_deleted(struct fd_link *link)
{
	return strip_deleted(link->name, link->len);
}

extern int dead_pid_conflict(void);

#endif /* __CR_FILES_REG_H__ */
