#ifndef __CR_PIPES_H__
#define __CR_PIPES_H__

#include "images/pipe-data.pb-c.h"
#include "images/pipe.pb-c.h"

extern struct collect_image_info pipe_cinfo;
extern struct collect_image_info pipe_data_cinfo;
extern const struct fdtype_ops pipe_dump_ops;

static inline u32 pipe_id(const struct fd_parms *p)
{
	return p->stat.st_ino;
}

#define NR_PIPES_WITH_DATA	1024

struct pipe_data_dump {
	int		img_type;
	unsigned int	nr;
	u32		ids[NR_PIPES_WITH_DATA];
};

extern int dump_one_pipe_data(struct pipe_data_dump *pd, int lfd, const struct fd_parms *p);

struct pipe_data_rst {
	PipeDataEntry		*pde;
	void *data;
	struct pipe_data_rst	*next;
};

#define PIPE_DATA_HASH_BITS	5
#define PIPE_DATA_HASH_SIZE	(1 << PIPE_DATA_HASH_BITS)
#define PIPE_DATA_HASH_MASK	(PIPE_DATA_HASH_SIZE - 1)

extern int do_collect_pipe_data(struct pipe_data_rst *,
		ProtobufCMessage *, struct cr_img *, struct pipe_data_rst **hash);
extern int restore_pipe_data(int img_type, int pfd, u32 id, struct pipe_data_rst **hash);

/*
 * The sequence of objects which should be restored:
 * pipe -> files struct-s -> fd-s.
 * pipe_entry describes  pipe's file structs-s.
 * A pipe doesn't have own properties, so it has no object.
 */

struct pipe_info {
	PipeEntry		*pe;
	struct list_head	pipe_list;	/* All pipe_info with the same pipe_id
						 * This is pure circular list without head */
	struct list_head	list;		/* list head for fdinfo_list_entry-s */
	struct file_desc	d;
	unsigned int		create : 1,
				reopen : 1;
};

#endif /* __CR_PIPES_H__ */
