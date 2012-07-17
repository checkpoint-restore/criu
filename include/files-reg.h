#ifndef FILES_REG_H__
#define FILES_REG_H__

#include "types.h"
#include "files.h"
#include "image.h"

#include "../protobuf/regfile.pb-c.h"
#include "../protobuf/ghost-file.pb-c.h"

struct cr_fdset;
struct fd_parms;

struct reg_file_info {
	struct file_desc	d;
	RegFileEntry		*rfe;
	char			*remap_path;
	char			*path;
};

extern int open_reg_by_id(u32 id);
extern int open_path_by_id(u32 id, int (*open_cb)(struct reg_file_info *, void *), void *arg);
extern void clear_ghost_files(void);
extern int collect_reg_files(void);

extern int dump_reg_file(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset);
extern int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p);

#endif /* FILES_REG_H__ */
