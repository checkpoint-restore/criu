#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#include "cr_options.h"
#include "list.h"
#include "xmalloc.h"
#include "log.h"
#include "servicefd.h"
#include "cr-service.h"
#include "action-scripts.h"
#include "pstree.h"

static const char *action_names[ACT_MAX] = {
	[ ACT_PRE_DUMP ]	= "pre-dump",
	[ ACT_POST_DUMP ]	= "post-dump",
	[ ACT_PRE_RESTORE ]	= "pre-restore",
	[ ACT_POST_RESTORE ]	= "post-restore",
	[ ACT_NET_LOCK ]	= "network-lock",
	[ ACT_NET_UNLOCK ]	= "network-unlock",
	[ ACT_SETUP_NS ]	= "setup-namespaces",
	[ ACT_POST_SETUP_NS ]	= "post-setup-namespaces",
	[ ACT_POST_RESUME ]	= "post-resume",
};

struct script {
	struct list_head node;
	char *path;
};

enum {
	SCRIPTS_NONE,
	SCRIPTS_SHELL,
	SCRIPTS_RPC
};

static int scripts_mode = SCRIPTS_NONE;
static int rpc_sk;
static LIST_HEAD(scripts);

int run_scripts(enum script_actions act)
{
	struct script *script;
	int ret = 0;
	char image_dir[PATH_MAX];
	const char *action = action_names[act];
	char root_item_pid[16];

	pr_debug("Running %s scripts\n", action);

	if (scripts_mode == SCRIPTS_NONE)
		return 0;

	if (scripts_mode == SCRIPTS_RPC) {
		pr_debug("\tRPC\n");
		ret = send_criu_rpc_script(act, (char *)action, rpc_sk);
		goto out;
	}

	if (setenv("CRTOOLS_SCRIPT_ACTION", action, 1)) {
		pr_perror("Can't set CRTOOLS_SCRIPT_ACTION=%s", action);
		return -1;
	}

	sprintf(image_dir, "/proc/%ld/fd/%d", (long) getpid(), get_service_fd(IMG_FD_OFF));
	if (setenv("CRTOOLS_IMAGE_DIR", image_dir, 1)) {
		pr_perror("Can't set CRTOOLS_IMAGE_DIR=%s", image_dir);
		return -1;
	}

	if (root_item) {
		snprintf(root_item_pid, sizeof(root_item_pid), "%d", root_item->pid.real);
		if (setenv("CRTOOLS_INIT_PID", root_item_pid, 1)) {
			pr_perror("Can't set CRTOOLS_INIT_PID=%s", root_item_pid);
			return -1;
		}
	}

	list_for_each_entry(script, &scripts, node) {
		pr_debug("\t[%s]\n", script->path);
		ret |= system(script->path);
	}

	unsetenv("CRTOOLS_SCRIPT_ACTION");

out:
	if (ret)
		pr_err("One of more action scripts failed\n");
	return ret;
}

int add_script(char *path)
{
	struct script *script;

	BUG_ON(scripts_mode == SCRIPTS_RPC);
	scripts_mode = SCRIPTS_SHELL;

	script = xmalloc(sizeof(struct script));
	if (script == NULL)
		return 1;

	script->path = path;
	list_add(&script->node, &scripts);

	return 0;
}

int add_rpc_notify(int sk)
{
	BUG_ON(scripts_mode == SCRIPTS_SHELL);
	scripts_mode = SCRIPTS_RPC;

	rpc_sk = sk;
	return 0;
}
