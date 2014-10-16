#ifndef __CR_TTY_H__
#define __CR_TTY_H__

#include <linux/major.h>

#include "files.h"

/* Kernel's limit */
#define TERMIOS_NCC	19

enum {
	TTY_TYPE_UNKNOWN	= 0,
	TTY_TYPE_PTM		= 1,
	TTY_TYPE_PTS		= 2,
	TTY_TYPE_CONSOLE	= 3,

	TTY_TYPE_MAX
};

#define PTMX_PATH	"/dev/ptmx"
#ifndef PTMX_MINOR
# define PTMX_MINOR 2
#endif
#define PTS_FMT		"/dev/pts/%d"

extern const struct fdtype_ops tty_dump_ops;

static inline int tty_type(int major, int minor)
{
	switch (major) {
	case TTYAUX_MAJOR:
		if (minor == 0 || minor == 2)
			return TTY_TYPE_PTM;
		else if (minor == 1)
			return TTY_TYPE_CONSOLE;
		break;
	case UNIX98_PTY_MASTER_MAJOR ... (UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT - 1):
		return TTY_TYPE_PTM;
	case UNIX98_PTY_SLAVE_MAJOR:
		return TTY_TYPE_PTS;
	}
	return TTY_TYPE_UNKNOWN;
}

static inline int is_tty(int major, int minor)
{
	return tty_type(major, minor) != TTY_TYPE_UNKNOWN;
}

static inline int is_pty(int type)
{
	return (type == TTY_TYPE_PTM || type == TTY_TYPE_PTS);
}

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
