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
extern int restore_pipe_data(int img_type, int pfd, u32 id, int bytes, off_t off);

#endif
