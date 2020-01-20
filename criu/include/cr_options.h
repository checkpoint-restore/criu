#ifndef __CR_OPTIONS_H__
#define __CR_OPTIONS_H__

#include <sys/types.h>
#include <stdbool.h>
#include "common/config.h"
#include "common/list.h"

/* Configuration and CLI parsing order defines */
#define PARSING_GLOBAL_CONF	1
#define PARSING_USER_CONF	2
#define PARSING_ENV_CONF	3
#define PARSING_CMDLINE_CONF	4
#define PARSING_ARGV		5
#define PARSING_RPC_CONF	6
#define PARSING_LAST		7

#define SET_CHAR_OPTS(__dest, __src) \
	do { \
		free(opts.__dest); \
		opts.__dest = xstrdup(__src); \
	} while(0)

/*
 * CPU capability options.
 */
#define CPU_CAP_NONE		(0u << 0)	/* Don't check capability at all */
#define CPU_CAP_FPU		(1u << 0)	/* Only FPU capability required */
#define CPU_CAP_CPU		(1u << 1)	/* Strict CPU capability required */
#define CPU_CAP_INS		(1u << 2)	/* Instructions CPU capability */
#define CPU_CAP_IMAGE		(1u << 3)	/* Write capability on dump and read on restore*/
#define CPU_CAP_ALL		(CPU_CAP_FPU | CPU_CAP_CPU | CPU_CAP_INS)
#define CPU_CAP_DEFAULT		(CPU_CAP_FPU | CPU_CAP_INS)

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

#define DEFAULT_TIMEOUT		10

struct irmap;

struct irmap_path_opt {
	struct list_head node;
	struct irmap *ir;
};

struct cr_options {
	int			final_state;
	int			check_extra_features;
	int			check_experimental_features;
	union {
		int		restore_detach;
		bool		daemon_mode;
	};
	int			restore_sibling;
	bool			ext_unix_sk;
	int			shell_job;
	int			handle_file_locks;
	int			tcp_established_ok;
	int			tcp_close;
	int			evasive_devices;
	int			link_remap_ok;
	int			log_file_per_pid;
	bool			swrk_restore;
	char			*output;
	char			*root;
	char			*pidfile;
	char			*freeze_cgroup;
	struct list_head	ext_mounts;
	struct list_head	inherit_fds;
	struct list_head	external;
	struct list_head	join_ns;
	char			*libdir;
	int			use_page_server;
	unsigned short		port;
	char			*addr;
	int			ps_socket;
	int			track_mem;
	char			*img_parent;
	int			auto_dedup;
	unsigned int		cpu_cap;
	int			force_irmap;
	char			**exec_cmd;
	unsigned int		manage_cgroups;
	char			*new_global_cg_root;
	char			*cgroup_props;
	char			*cgroup_props_file;
	struct list_head	new_cgroup_roots;
	bool			autodetect_ext_mounts;
	int			enable_external_sharing;
	int			enable_external_masters;
	bool			aufs;		/* auto-detected, not via cli */
	bool			overlayfs;
#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
	bool			has_binfmt_misc; /* auto-detected */
#endif
	size_t			ghost_limit;
	struct list_head	irmap_scan_paths;
	bool			lsm_supplied;
	char			*lsm_profile;
	unsigned int		timeout;
	unsigned int		empty_ns;
	int			tcp_skip_in_flight;
	bool			lazy_pages;
	char			*work_dir;

	/*
	 * When we scheduler for removal some functionality we first
	 * deprecate it and it sits in criu for some time. By default
	 * the deprecated stuff is not working, but it's still possible
	 * to turn one ON while the code is in.
	 */
	int			deprecated_ok;
	int			display_stats;
	int			weak_sysctls;
	int			status_fd;
	bool			orphan_pts_master;
	int			remote;
	pid_t			tree_id;
	int			log_level;
	char			*imgs_dir;
	char			*tls_cacert;
	char			*tls_cacrl;
	char			*tls_cert;
	char			*tls_key;
	int			tls;
	int			tls_no_cn_verify;
};

extern struct cr_options opts;
char *rpc_cfg_file;

extern int parse_options(int argc, char **argv, bool *usage_error, bool *has_exec_cmd, int state);
extern int check_options();
extern void init_opts();

#endif /* __CR_OPTIONS_H__ */
