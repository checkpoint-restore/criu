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
extern int collect_tty(void);
extern int tty_is_master(struct fdinfo_list_entry *le);
extern int tty_prepare_shared(void);
extern int tty_setup_orphan_slavery(const struct cr_options *opts);

#endif /* CR_TTY_H__ */
