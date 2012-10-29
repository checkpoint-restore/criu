#ifndef CR_TTY_H__
#define CR_TTY_H__

#include "files.h"
#include "crtools.h"

/* Kernel's limit */
#define TERMIOS_NCC	19

#define PTMX_PATH	"/dev/ptmx"
#ifndef PTMX_MINOR
# define PTMX_MINOR 2
#endif
#define PTS_FMT		"/dev/pts/%d"

extern int dump_tty(struct fd_parms *p, int lfd, const struct cr_fdset *set);
extern int dump_verify_tty_sids(void);
extern int collect_tty(void);
extern int prepare_shared_tty(void);
extern int tty_setup_slavery(void);

extern int tty_verify_active_pairs(void);

extern int tty_prep_fds(void);
extern void tty_fini_fds(void);

#endif /* CR_TTY_H__ */
