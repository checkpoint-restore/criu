#ifndef __CR_SETPROCTITLE_H__
#define __CR_SETPROCTITLE_H__

extern void __setproctitle_init(int argc, char *argv[], char *envp[]);
extern void __setproctitle(const char *fmt, ...);

#endif /* __CR_SETPROCTITLE_H__ */
