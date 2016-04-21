#ifndef __CR_ACTION_SCRIPTS_H__
#define __CR_ACTION_SCRIPTS_H__

enum script_actions {
	ACT_PRE_DUMP		= 0,
	ACT_POST_DUMP		= 1,
	ACT_PRE_RESTORE		= 2,
	ACT_POST_RESTORE	= 3,
	ACT_NET_LOCK		= 4,
	ACT_NET_UNLOCK		= 5,
	ACT_SETUP_NS		= 6,
	ACT_POST_SETUP_NS	= 7,
	ACT_POST_RESUME		= 8,

	ACT_MAX
};

extern int add_script(char *path);
extern int add_rpc_notify(int sk);
extern int run_scripts(enum script_actions);
extern int send_criu_rpc_script(enum script_actions act, char *name, int arg);

#endif /* __CR_ACTION_SCRIPTS_H__ */
