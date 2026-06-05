#ifndef _CRIU_LINUX_MOUNT_H
#define _CRIU_LINUX_MOUNT_H

#include "common/config.h"
#include "compel/plugins/std/syscall-codes.h"

/* Copied from /usr/include/sys/mount.h */

#ifndef FSOPEN_CLOEXEC
/* The type of fsconfig call made.   */
enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0, /* Set parameter, supplying no value */
#define FSCONFIG_SET_FLAG FSCONFIG_SET_FLAG
	FSCONFIG_SET_STRING = 1, /* Set parameter, supplying a string value */
#define FSCONFIG_SET_STRING FSCONFIG_SET_STRING
	FSCONFIG_SET_BINARY = 2, /* Set parameter, supplying a binary blob value */
#define FSCONFIG_SET_BINARY FSCONFIG_SET_BINARY
	FSCONFIG_SET_PATH = 3, /* Set parameter, supplying an object by path */
#define FSCONFIG_SET_PATH FSCONFIG_SET_PATH
	FSCONFIG_SET_PATH_EMPTY = 4, /* Set parameter, supplying an object by (empty) path */
#define FSCONFIG_SET_PATH_EMPTY FSCONFIG_SET_PATH_EMPTY
	FSCONFIG_SET_FD = 5, /* Set parameter, supplying an object by fd */
#define FSCONFIG_SET_FD FSCONFIG_SET_FD
	FSCONFIG_CMD_CREATE = 6, /* Invoke superblock creation */
#define FSCONFIG_CMD_CREATE FSCONFIG_CMD_CREATE
	FSCONFIG_CMD_RECONFIGURE = 7, /* Invoke superblock reconfiguration */
#define FSCONFIG_CMD_RECONFIGURE FSCONFIG_CMD_RECONFIGURE
};

#endif // FSOPEN_CLOEXEC

/* fsopen flags. With the redundant definition, we check if the kernel,
 * glibc value and our value still match.
 */
#define FSOPEN_CLOEXEC 0x00000001

#ifndef MS_MGC_VAL
/* Magic mount flag number. Has to be or-ed to the flag values.  */
#define MS_MGC_VAL 0xc0ed0000 /* Magic flag number to indicate "new" flags */
#define MS_MGC_MSK 0xffff0000 /* Magic flag number mask */
#endif

/*
 * statmount(2) / statx(2) bits used to read a mount's superblock options
 * (#3029). The flags are #ifndef-guarded; the structures are CRIU-local
 * (cr_ prefixed) on purpose: libc <sys/mount.h> (e.g. glibc 2.39) may
 * declare struct statmount with the pre-6.11 layout that lacks mnt_opts,
 * so we must not reuse or redefine it. Field offsets are checked with
 * BUILD_BUG_ON at the call site.
 */
#include <stdint.h>

/* statmount(2), Linux 6.8. Fallback for build hosts whose headers lack it. */
#ifndef __NR_statmount
#define __NR_statmount 457
#endif

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U /* Want/got stx_mnt_id (unique), Linux 6.8 */
#endif

#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC 0x00000001U /* Want/got sb_... */
#endif

#ifndef STATMOUNT_MNT_OPTS
#define STATMOUNT_MNT_OPTS 0x00000080U /* Want/got mnt_opts, Linux 6.11 */
#endif

/* Request structure for statmount(2)/listmount(2), original (VER0) layout. */
struct cr_mnt_id_req {
	uint32_t size;
	uint32_t spare;
	uint64_t mnt_id;
	uint64_t param;
};
#define CR_MNT_ID_REQ_SIZE_VER0 24 /* sizeof the first published struct */

/*
 * Reply structure for statmount(2). Prefix matches the kernel uapi up to the
 * fields CRIU reads (mnt_opts, sb_magic); the trailing spare keeps room for
 * the variable-length str[] area that follows.
 */
struct cr_statmount {
	uint32_t size;		/* Total bytes written by the kernel */
	uint32_t mnt_opts;	/* [str] Mount options string (Linux 6.11) */
	uint64_t mask;		/* What statmount(2) actually filled in */
	uint32_t sb_dev_major;
	uint32_t sb_dev_minor;
	uint64_t sb_magic;	/* Filesystem magic (STATMOUNT_SB_BASIC) */
	uint32_t sb_flags;
	uint32_t fs_type;	/* [str] */
	uint64_t mnt_id;
	uint64_t mnt_parent_id;
	uint32_t mnt_id_old;
	uint32_t mnt_parent_id_old;
	uint64_t mnt_attr;
	uint64_t mnt_propagation;
	uint64_t mnt_peer_group;
	uint64_t mnt_master;
	uint64_t propagate_from;
	uint32_t mnt_root;	/* [str] */
	uint32_t mnt_point;	/* [str] */
	uint64_t __spare2[50];
	char str[]; /* Variable size part containing strings */
};

/*
 * Minimal statx(2) reply: only stx_mask and stx_mnt_id are read. libc may not
 * wrap statx() (musl), so this is called via syscall(); the layout up to
 * stx_mnt_id must match the kernel uapi exactly (checked with BUILD_BUG_ON).
 */
struct cr_statx {
	uint32_t stx_mask;
	uint32_t __pad_blksize;
	uint64_t __pad_attributes;
	uint32_t __pad_nlink;
	uint32_t __pad_uid;
	uint32_t __pad_gid;
	uint16_t __pad_mode;
	uint16_t __pad_spare0;
	uint64_t __pad_ino;
	uint64_t __pad_size;
	uint64_t __pad_blocks;
	uint64_t __pad_attributes_mask;
	uint64_t __pad_times[8]; /* atime, btime, ctime, mtime (4 x 16 bytes) */
	uint32_t __pad_rdev_major;
	uint32_t __pad_rdev_minor;
	uint32_t __pad_dev_major;
	uint32_t __pad_dev_minor;
	uint64_t stx_mnt_id; /* Offset 144 */
	uint64_t __pad_tail[14]; /* Pad past the kernel's 256-byte write */
};

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#endif
