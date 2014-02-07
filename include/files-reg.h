#ifndef __CR_FILES_REG_H__
#define __CR_FILES_REG_H__

#include "asm/types.h"
#include "files.h"
#include "image.h"

#include "protobuf/regfile.pb-c.h"
#include "protobuf/ghost-file.pb-c.h"

struct cr_fdset;
struct fd_parms;

struct file_remap {
	char *path;
	unsigned int users;
};

struct reg_file_info {
	struct file_desc	d;
	RegFileEntry		*rfe;
	struct file_remap	*remap;
	char			*path;
};

extern int open_reg_by_id(u32 id);
extern int open_path(struct file_desc *, int (*open_cb)(struct reg_file_info *, void *), void *arg);
extern void clear_ghost_files(void);

extern int prepare_shared_reg_files(void);

extern const struct fdtype_ops regfile_dump_ops;
extern int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p);

extern struct file_remap *lookup_ghost_remap(u32 dev, u32 ino);
extern void remap_put(struct file_remap *remap);
extern struct file_desc *collect_special_file(u32 id);

extern struct collect_image_info reg_file_cinfo;
extern struct collect_image_info remap_cinfo;

extern void delete_link_remaps(void);
extern void free_link_remaps(void);

#endif /* __CR_FILES_REG_H__ */
