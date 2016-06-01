#ifndef __CR_SERVICE_FD_H__
#define __CR_SERVICE_FD_H__

#include <stdbool.h>

enum sfd_type {
	SERVICE_FD_MIN,

	LOG_FD_OFF,
	IMG_FD_OFF,
	PROC_FD_OFF,	/* fd with /proc for all proc_ calls */
	CTL_TTY_OFF,
	SELF_STDIN_OFF,
	CR_PROC_FD_OFF, /* some other's proc fd.
			 *  For dump -- target ns' proc
			 *  For restore -- CRIU ns' proc
			 */
	ROOT_FD_OFF,	/* Root of the namespace we dump/restore */
	CGROUP_YARD,
	USERNSD_SK,	/* Socket for usernsd */
	NS_FD_OFF,	/* Node's net namespace fd */

	SERVICE_FD_MAX
};

extern int clone_service_fd(int id);
extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern int reserve_service_fd(enum sfd_type type);
extern int install_service_fd(enum sfd_type type, int fd);
extern int close_service_fd(enum sfd_type type);
extern bool is_service_fd(int fd, enum sfd_type type);
extern bool is_any_service_fd(int fd);
extern int service_fd_min_fd(void);

#endif /* __CR_SERVICE_FD_H__ */
