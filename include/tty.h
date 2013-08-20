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

extern const struct fdtype_ops tty_dump_ops;
extern int dump_verify_tty_sids(void);
extern struct collect_image_info tty_info_cinfo;
extern struct collect_image_info tty_cinfo;
extern int prepare_shared_tty(void);
extern int tty_setup_slavery(void);

extern int tty_verify_active_pairs(void);

extern int tty_prep_fds(void);
extern void tty_fini_fds(void);

#define OPT_SHELL_JOB	"shell-job"

#endif /* __CR_TTY_H__ */
