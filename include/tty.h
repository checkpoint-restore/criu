#ifndef __CR_TTY_H__
#define __CR_TTY_H__

#include "files.h"
#include "crtools.h"

/* Kernel's limit */
#define TERMIOS_NCC	19

#define PTMX_PATH	"/dev/ptmx"
#ifndef PTMX_MINOR
# define PTMX_MINOR 2
#endif
#define PTS_FMT		"/dev/pts/%d"

extern int dump_tty(struct fd_parms *p, int lfd, const int fdinfo);
extern int dump_verify_tty_sids(void);
extern int collect_tty(void);
extern int prepare_shared_tty(void);
extern int tty_setup_slavery(void);

extern int tty_verify_active_pairs(void);

extern int tty_prep_fds(struct cr_options *opts);
extern void tty_fini_fds(void);

#endif /* __CR_TTY_H__ */
