#ifndef __CR_OPTIONS_H__
#define __CR_OPTIONS_H__

#include <stdbool.h>

#include "list.h"

struct script {
	struct list_head node;
	char *path;
	int arg;
};

#define SCRIPT_RPC_NOTIFY	(char *)0x1

/*
 * CPU capability options.
 */
#define CPU_CAP_FPU		(1u)
#define CPU_CAP_ALL		(-1u)

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	char			*show_fmt;
	bool			check_ms_kernel;
	bool			show_pages_content;
	bool			restore_detach;
	bool			ext_unix_sk;
	bool			shell_job;
	bool			handle_file_locks;
	bool			tcp_established_ok;
	bool			evasive_devices;
	bool			link_remap_ok;
	unsigned int		rst_namespaces_flags;
	bool			log_file_per_pid;
	char			*output;
	char			*root;
	char			*pidfile;
	struct list_head	veth_pairs;
	struct list_head	scripts;
	char			*libdir;
	bool			use_page_server;
	unsigned short		ps_port;
	char			*addr;
	bool			track_mem;
	char			*img_parent;
	bool			auto_dedup;
	unsigned int		cpu_cap;
	bool			force_irmap;
	char			**exec_cmd;
};

extern struct cr_options opts;

extern void init_opts(void);

#endif /* __CR_OPTIONS_H__ */
