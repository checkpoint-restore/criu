#ifndef __CR_KERNDAT_H__
#define __CR_KERNDAT_H__

#include <stdbool.h>
#include "int.h"
#include "common/config.h"
#include "asm/kerndat.h"
#include "util-vdso.h"

struct stat;

/*
 * kerndat stands for "kernel data" and is a collection
 * of run-time information about current kernel
 */

extern int kerndat_init(void);

enum pagemap_func {
	PM_UNKNOWN,
	PM_DISABLED, /* /proc/pid/pagemap doesn't open (user mode) */
	PM_FLAGS_ONLY, /* pagemap zeroes pfn part (user mode) */
	PM_FULL,
};

enum loginuid_func {
	LUID_NONE,
	LUID_READ,
	LUID_FULL,
};

struct kerndat_s {
	u32 magic1, magic2;
	dev_t shmem_dev;
	int last_cap;
	u64 zero_page_pfn;
	bool has_dirty_track;
	bool has_memfd;
	bool has_fdinfo_lock;
	unsigned long task_size;
	bool ipv6;
	enum loginuid_func luid;
	bool compat_cr;
	bool sk_ns;
	bool sk_unix_file;
	bool tun_ns;
	enum pagemap_func pmap;
	unsigned int has_xtlocks;
	unsigned long mmap_min_addr;
	bool has_tcp_half_closed;
	bool stack_guard_gap_hidden;
	int lsm;
	bool apparmor_ns_dumping_enabled;
	bool has_uffd;
	unsigned long uffd_features;
	bool has_thp_disable;
	bool can_map_vdso;
	bool vdso_hint_reliable;
	struct vdso_symtable vdso_sym;
#ifdef CONFIG_COMPAT
	struct vdso_symtable vdso_sym_compat;
#endif
	bool has_nsid;
	bool has_link_nsid;
	unsigned int sysctl_nr_open;
	bool x86_has_ptrace_fpu_xsave_bug;
	bool has_inotify_setnextwd;
	bool has_kcmp_epoll_tfd;
	bool has_fsopen;
	bool has_clone3_set_tid;
	bool has_timens;
	bool has_newifindex;
	bool has_pidfd_open;
	bool has_pidfd_getfd;
	bool has_nspid;
	bool has_nftables_concat;
};

extern struct kerndat_s kdat;

enum {
	KERNDAT_FS_STAT_DEVPTS,
	KERNDAT_FS_STAT_DEVTMPFS,
	KERNDAT_FS_STAT_BINFMT_MISC,

	KERNDAT_FS_STAT_MAX
};

/*
 * Check whether the fs @which with kdevice @kdev
 * is the same as host's. If yes, this means that
 * the fs mount is shared with host, if no -- it's
 * a new (likely virtuzlized) fs instance.
 */
extern int kerndat_fs_virtualized(unsigned int which, u32 kdev);

extern int kerndat_has_nspid(void);

#endif /* __CR_KERNDAT_H__ */
