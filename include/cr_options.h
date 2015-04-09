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

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	char			*show_fmt;
	bool			check_ms_kernel;
	bool			show_pages_content;
	union {
		bool		restore_detach;
		bool		daemon_mode;
	};
	bool			restore_sibling;
	bool			ext_unix_sk;
	bool			shell_job;
	bool			handle_file_locks;
	bool			tcp_established_ok;
	bool			evasive_devices;
	bool			link_remap_ok;
	unsigned int		rst_namespaces_flags;
	bool			log_file_per_pid;
	bool			swrk_restore;
	char			*output;
	char			*root;
	char			*pidfile;
	struct list_head	veth_pairs;
	struct list_head	scripts;
	struct list_head	ext_mounts;
	struct list_head	inherit_fds;
	char			*libdir;
	bool			use_page_server;
	unsigned short		ps_port;
	char			*addr;
	int			ps_socket;
	bool			track_mem;
	char			*img_parent;
	bool			auto_dedup;
	unsigned int		cpu_cap;
	bool			force_irmap;
	char			**exec_cmd;
	bool			manage_cgroups;
	char			*new_global_cg_root;
	struct list_head	new_cgroup_roots;
	bool			autodetect_ext_mounts;
	bool			enable_external_sharing;
	bool			enable_external_masters;
	bool			aufs;		/* auto-deteced, not via cli */
};

extern struct cr_options opts;

extern void init_opts(void);

#endif /* __CR_OPTIONS_H__ */
