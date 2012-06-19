#ifndef __CR_PIPES_H__
#define __CR_PIPES_H__
extern int collect_pipes(void);
extern void mark_pipe_master(void);
int dump_pipe(struct fd_parms *p, int lfd,
			     const struct cr_fdset *cr_fdset);
#endif
