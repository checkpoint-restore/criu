#ifndef UNIX_DIAG_H__
#define UNIX_DIAG_H__

#include "types.h"

struct unix_diag_req {
	u8	sdiag_family;
	u8	sdiag_protocol;
	u16	pad;
	u32	udiag_states;
	u32	udiag_ino;
	u32	udiag_show;
	u32	udiag_cookie[2];
};

#define UDIAG_SHOW_NAME		0x00000001	/* show name (not path) */
#define UDIAG_SHOW_VFS		0x00000002	/* show VFS inode info */
#define UDIAG_SHOW_PEER		0x00000004	/* show peer socket info */
#define UDIAG_SHOW_ICONS	0x00000008	/* show pending connections */
#define UDIAG_SHOW_RQLEN	0x00000010	/* show skb receive queue len */

struct unix_diag_msg {
	u8	udiag_family;
	u8	udiag_type;
	u8	udiag_state;
	u8	pad;

	u32	udiag_ino;
	u32	udiag_cookie[2];
};

enum {
	UNIX_DIAG_NAME,
	UNIX_DIAG_VFS,
	UNIX_DIAG_PEER,
	UNIX_DIAG_ICONS,
	UNIX_DIAG_RQLEN,

	UNIX_DIAG_MAX,
};

struct unix_diag_vfs {
	u32	udiag_vfs_ino;
	u32	udiag_vfs_dev;
};

#endif /* UNIX_DIAG_H__ */
