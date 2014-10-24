#ifndef __CR_ACTION_SCRIPTS_H__
#define __CR_ACTION_SCRIPTS_H__

struct script {
	struct list_head node;
	char *path;
	int arg;
};

#define SCRIPT_RPC_NOTIFY	(char *)0x1

enum script_actions {
	ACT_POST_DUMP		= 0,
	ACT_POST_RESTORE	= 1,
	ACT_NET_LOCK		= 2,
	ACT_NET_UNLOCK		= 3,
	ACT_SETUP_NS		= 4,

	ACT_MAX
};

extern int add_script(char *path, int arg);
extern int run_scripts(enum script_actions);
extern int send_criu_rpc_script(enum script_actions act, char *name, int arg);

#endif /* __CR_ACTION_SCRIPTS_H__ */
