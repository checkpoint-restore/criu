#ifndef __CR_ACTION_SCRIPTS_H__
#define __CR_ACTION_SCRIPTS_H__

struct script {
	struct list_head node;
	char *path;
	int arg;
};

#define SCRIPT_RPC_NOTIFY	(char *)0x1

enum script_actions {
	ACT_POST_DUMP,
	ACT_POST_RESTORE,
	ACT_NET_LOCK,
	ACT_NET_UNLOCK,
	ACT_SETUP_NS,
};

extern int add_script(char *path, int arg);
extern int run_scripts(enum script_actions);

#endif /* __CR_ACTION_SCRIPTS_H__ */
