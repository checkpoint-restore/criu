#ifndef __CR_PIPES_H__
#define __CR_PIPES_H__
extern int collect_pipes(void);
extern void mark_pipe_master(void);
int dump_pipe(struct fd_parms *p, int lfd,
			     const struct cr_fdset *cr_fdset);

#define NR_PIPES_WITH_DATA	1024

struct pipe_data_dump {
	int		img_type;
	unsigned int	nr;
	u32		ids[NR_PIPES_WITH_DATA];
};

extern int dump_one_pipe_data(struct pipe_data_dump *pd, int lfd, const struct fd_parms *p);

struct pipe_data_rst {
	struct pipe_data_entry	pde;
	struct pipe_data_rst	*next;
};

#define PIPE_DATA_HASH_BITS	5
#define PIPE_DATA_HASH_SIZE	(1 << PIPE_DATA_HASH_BITS)
#define PIPE_DATA_HASH_MASK	(PIPE_DATA_HASH_SIZE - 1)

extern int collect_pipe_data(int img_type, struct pipe_data_rst **hash);
extern int restore_pipe_data(int img_type, int pfd, u32 id, struct pipe_data_rst **hash);

#endif
