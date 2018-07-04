#ifndef __CR_KERNDAT_H__
#define __CR_KERNDAT_H__

#include <stdbool.h>
#include "int.h"
#include "common/config.h"
#include "asm/kerndat.h"
#ifdef CONFIG_VDSO
#include "util-vdso.h"
#endif

struct stat;

/*
 * kerndat stands for "kernel data" and is a collection
 * of run-time information about current kernel
 */

extern int kerndat_init(void);
extern int kerndat_get_dirty_track(void);
extern int kerndat_fdinfo_has_lock(void);
extern int kerndat_loginuid(void);
extern int kerndat_files_stat(bool early);

enum pagemap_func {
	PM_UNKNOWN,
	PM_DISABLED,	/* /proc/pid/pagemap doesn't open (user mode) */
	PM_FLAGS_ONLY,	/* pagemap zeroes pfn part (user mode) */
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
	bool has_uffd;
	unsigned long uffd_features;
	bool has_thp_disable;
	bool can_map_vdso;
	bool vdso_hint_reliable;
#ifdef CONFIG_VDSO
	struct vdso_symtable	vdso_sym;
#ifdef CONFIG_COMPAT
	struct vdso_symtable	vdso_sym_compat;
#endif
#endif
	bool has_nsid;
	bool has_link_nsid;
	unsigned int sysctl_nr_open;
	unsigned long files_stat_max_files;
	bool x86_has_ptrace_fpu_xsave_bug;
	bool has_inotify_setnextwd;
	bool has_kcmp_epoll_tfd;
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

extern int kerndat_tcp_repair();
extern int kerndat_uffd(void);

#endif /* __CR_KERNDAT_H__ */
