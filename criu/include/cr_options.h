#ifndef __CR_OPTIONS_H__
#define __CR_OPTIONS_H__

#include <stdbool.h>

#include "list.h"

/*
 * CPU capability options.
 */
#define CPU_CAP_NONE		(0u)
#define CPU_CAP_ALL		(-1u)
#define CPU_CAP_FPU		(1u)		/* Only FPU capability required */
#define CPU_CAP_CPU		(2u)		/* Strict CPU capability required */
#define CPU_CAP_INS		(4u)		/* Instructions CPU capatibility */
#define CPU_CAP_DEFAULT		(CPU_CAP_FPU)

struct cg_root_opt {
	struct list_head node;
	char *controller;
	char *newroot;
};

/*
 * Cgroup management options.
 */
#define CG_MODE_IGNORE		(0u << 0)	/* Zero is important here */
#define CG_MODE_NONE		(1u << 0)
#define CG_MODE_PROPS		(1u << 1)
#define CG_MODE_SOFT		(1u << 2)
#define CG_MODE_FULL		(1u << 3)
#define CG_MODE_STRICT		(1u << 4)

#define CG_MODE_DEFAULT		(CG_MODE_SOFT)

/*
 * Ghost file size we allow to carry by default.
 */
#define DEFAULT_GHOST_LIMIT	(1 << 20)

#define DEFAULT_TIMEOUT		5

struct irmap;

struct irmap_path_opt {
	struct list_head node;
	struct irmap *ir;
};

struct external {
	struct list_head node;
	char *id;
};

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	char			*show_fmt;
	bool			check_extra_features;
	bool			check_experimental_features;
	bool			show_pages_content;
	union {
		bool		restore_detach;
		bool		daemon_mode;
	};
	bool			restore_sibling;
	bool			ext_unix_sk;
	struct list_head        ext_unixsk_ids;
	bool			shell_job;
	bool			handle_file_locks;
	bool			tcp_established_ok;
	bool			evasive_devices;
	bool			link_remap_ok;
	bool			log_file_per_pid;
	bool			swrk_restore;
	char			*output;
	char			*root;
	char			*pidfile;
	char			*freeze_cgroup;
	struct list_head	veth_pairs;
	struct list_head	ext_mounts;
	struct list_head	inherit_fds;
	struct list_head	external;
	char			*libdir;
	bool			use_page_server;
	unsigned short		port;
	char			*addr;
	int			ps_socket;
	bool			track_mem;
	char			*img_parent;
	bool			auto_dedup;
	unsigned int		cpu_cap;
	bool			force_irmap;
	char			**exec_cmd;
	unsigned int		manage_cgroups;
	char			*new_global_cg_root;
	struct list_head	new_cgroup_roots;
	bool			autodetect_ext_mounts;
	bool			enable_external_sharing;
	bool			enable_external_masters;
	bool			aufs;		/* auto-deteced, not via cli */
	bool			overlayfs;
	size_t			ghost_limit;
	struct list_head	irmap_scan_paths;
	bool			lsm_supplied;
	char			*lsm_profile;
	unsigned int		timeout;
	unsigned int		empty_ns;
};

extern struct cr_options opts;

extern void init_opts(void);

extern int add_external(char *key);

#endif /* __CR_OPTIONS_H__ */
