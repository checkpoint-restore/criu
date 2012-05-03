#ifndef __CR_PIPES_H__
#define __CR_PIPES_H__
extern int collect_pipes(void);
extern void mark_pipe_master(void);
int init_pipes_dump(void);
void fini_pipes_dump(void);
int dump_one_pipe(int lfd, u32 id, const struct fd_parms *p);
#endif
