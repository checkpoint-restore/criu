#ifndef __CR_TTY_H__
#define __CR_TTY_H__

#include <linux/major.h>
#include <linux/vt.h>

#include "files.h"

/* Kernel's limit */
#define TERMIOS_NCC 19

/* Popular serial console's majors, which not defined in <linux/major.h> */
#define USB_SERIAL_MAJOR       188
#define LOW_DENSE_SERIAL_MAJOR 204

extern const struct fdtype_ops tty_dump_ops;

struct tty_driver;
struct tty_driver *get_tty_driver(dev_t rdev, dev_t dev);
static inline int is_tty(dev_t rdev, dev_t dev)
{
	return get_tty_driver(rdev, dev) != NULL;
}

extern int tty_post_actions(void);
extern int dump_verify_tty_sids(void);
extern struct collect_image_info tty_info_cinfo;
extern struct collect_image_info tty_cinfo;
extern struct collect_image_info tty_cdata;

struct mount_info;
extern int devpts_restore(struct mount_info *pm);

extern int tty_prep_fds(void);
extern int tty_init_restore(void);

extern int devpts_check_bindmount(struct mount_info *m);

#define OPT_SHELL_JOB "shell-job"

#endif /* __CR_TTY_H__ */
