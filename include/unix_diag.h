#ifndef __CR_UNIX_DIAG_H__
#define __CR_UNIX_DIAG_H__

#include "asm/types.h"

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
#define UDIAG_SHOW_MEMINFO	0x00000020	/* show memory info of a socket */

struct unix_diag_msg {
	u8	udiag_family;
	u8	udiag_type;
	u8	udiag_state;
	u8	pad;

	u32	udiag_ino;
	u32	udiag_cookie[2];
};

enum {
	SK_MEMINFO_RMEM_ALLOC,
	SK_MEMINFO_RCVBUF,
	SK_MEMINFO_WMEM_ALLOC,
	SK_MEMINFO_SNDBUF,
	SK_MEMINFO_FWD_ALLOC,
	SK_MEMINFO_WMEM_QUEUED,
	SK_MEMINFO_OPTMEM,

	SK_MEMINFO_VARS,
};

enum {
	UNIX_DIAG_NAME,
	UNIX_DIAG_VFS,
	UNIX_DIAG_PEER,
	UNIX_DIAG_ICONS,
	UNIX_DIAG_RQLEN,
	UNIX_DIAG_MEMINFO,
	UNIX_DIAG_SHUTDOWN,

	UNIX_DIAG_MAX,
};

struct unix_diag_vfs {
	u32	udiag_vfs_ino;
	u32	udiag_vfs_dev;
};

struct unix_diag_rqlen {
	u32	udiag_rqueue;
	u32	udiag_wqueue;
};

#endif /* __CR_UNIX_DIAG_H__ */
