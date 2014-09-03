#ifndef __CR_ACTION_SCRIPTS_H__
#define __CR_ACTION_SCRIPTS_H__

struct script {
	struct list_head node;
	char *path;
	int arg;
};

#define SCRIPT_RPC_NOTIFY	(char *)0x1

extern int add_script(char *path, int arg);
extern int run_scripts(char *action);
#endif /* __CR_ACTION_SCRIPTS_H__ */
