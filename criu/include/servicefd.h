#ifndef __CR_SERVICE_FD_H__
#define __CR_SERVICE_FD_H__

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "criu-log.h"

enum sfd_type {
	SERVICE_FD_MIN,

	LOG_FD_OFF,
	IMG_FD_OFF,
	IMG_STREAMER_FD_OFF,
	PROC_FD_OFF, /* fd with /proc for all proc_ calls */
	PROC_PID_FD_OFF,
	PROC_SELF_FD_OFF,
	CR_PROC_FD_OFF, /* some other's proc fd:
				 *  - For dump -- target ns' proc
				 *  - For restore -- CRIU ns' proc
				 */
	ROOT_FD_OFF, /* Root of the namespace we dump/restore */
	CGROUP_YARD,
	USERNSD_SK, /* Socket for usernsd */
	NS_FD_OFF, /* Node's net namespace fd */
	TRANSPORT_FD_OFF, /* to transfer file descriptors */
	RPC_SK_OFF,
	FDSTORE_SK_OFF,

	SERVICE_FD_MAX
};

struct pstree_item;
extern bool sfds_protected;

extern const char *sfd_type_name(enum sfd_type type);
extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern bool is_any_service_fd(int fd);
extern bool is_service_fd(int fd, enum sfd_type type);
extern int service_fd_min_fd(struct pstree_item *item);
extern int install_service_fd(enum sfd_type type, int fd);
extern int close_service_fd(enum sfd_type type);
extern void __close_service_fd(enum sfd_type type);
extern int clone_service_fd(struct pstree_item *me);

#endif /* __CR_SERVICE_FD_H__ */
