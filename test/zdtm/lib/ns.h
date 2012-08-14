#ifndef __ZDTM_NS__
#define __ZDTM_NS__

extern volatile sig_atomic_t sig_received;
extern char *pidfile;

extern void ns_create(int argc, char **argv);
extern int ns_init(int argc, char **argv);

extern void test_waitsig(void);
extern void parseargs(int, char **);

#endif
