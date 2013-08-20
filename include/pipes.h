#ifndef __CR_PIPES_H__
#define __CR_PIPES_H__

#include "protobuf/pipe-data.pb-c.h"

extern struct collect_image_info pipe_cinfo;
extern int collect_pipes(void);
extern void mark_pipe_master(void);
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

extern int collect_pipe_data(int img_type, struct pipe_data_rst **hash);
extern int restore_pipe_data(int img_type, int pfd, u32 id, struct pipe_data_rst **hash);

#endif /* __CR_PIPES_H__ */
