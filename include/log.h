#ifndef LOG_H__
#define LOG_H__

extern int init_log(const char *name);
extern void fini_log(void);
extern int get_logfd(void);

#endif /* LOG_H__ */
