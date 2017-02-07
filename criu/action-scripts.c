#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#include "cr_options.h"
#include "common/list.h"
#include "xmalloc.h"
#include "log.h"
#include "servicefd.h"
#include "cr-service.h"
#include "action-scripts.h"
#include "pstree.h"
#include "common/bug.h"
#include "util.h"
#include <sys/un.h>
#include <sys/socket.h>
#include "common/scm.h"

static const char *action_names[ACT_MAX] = {
	[ ACT_PRE_DUMP ]	= "pre-dump",
	[ ACT_POST_DUMP ]	= "post-dump",
	[ ACT_PRE_RESTORE ]	= "pre-restore",
	[ ACT_POST_RESTORE ]	= "post-restore",
	[ ACT_NET_LOCK ]	= "network-lock",
	[ ACT_NET_UNLOCK ]	= "network-unlock",
	[ ACT_SETUP_NS ]	= "setup-namespaces",
	[ ACT_POST_SETUP_NS ]	= "post-setup-namespaces",
	[ ACT_PRE_RESUME ]	= "pre-resume",
	[ ACT_POST_RESUME ]	= "post-resume",
	[ ACT_ORPHAN_PTS_MASTER ] = "orphan-pts-master",
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

static int run_shell_scripts(const char *action)
{
	int retval = 0;
	struct script *script;
	char image_dir[PATH_MAX];
	static unsigned env_set = 0;

#define ENV_IMGDIR	0x1
#define ENV_ROOTPID	0x2

	if (setenv("CRTOOLS_SCRIPT_ACTION", action, 1)) {
		pr_perror("Can't set CRTOOLS_SCRIPT_ACTION=%s", action);
		return -1;
	}

	if (!(env_set & ENV_IMGDIR)) {
		sprintf(image_dir, "/proc/%ld/fd/%d", (long) getpid(), get_service_fd(IMG_FD_OFF));
		if (setenv("CRTOOLS_IMAGE_DIR", image_dir, 1)) {
			pr_perror("Can't set CRTOOLS_IMAGE_DIR=%s", image_dir);
			return -1;
		}
		env_set |= ENV_IMGDIR;
	}

	if (!(env_set & ENV_ROOTPID) && root_item) {
		int pid;
		char root_item_pid[16];

		pid = root_item->pid->real;
		if (pid != -1) {
			snprintf(root_item_pid, sizeof(root_item_pid), "%d", pid);
			if (setenv("CRTOOLS_INIT_PID", root_item_pid, 1)) {
				pr_perror("Can't set CRTOOLS_INIT_PID=%s", root_item_pid);
				return -1;
			}
			env_set |= ENV_ROOTPID;
		}
	}

	list_for_each_entry(script, &scripts, node) {
		int err;
		pr_debug("\t[%s]\n", script->path);
		err = cr_system(-1, -1, -1, script->path,
				(char *[]) { script->path, NULL }, 0);
		if (err)
			pr_err("Script %s exited with %d\n", script->path, err);
		retval |= err;
	}

	unsetenv("CRTOOLS_SCRIPT_ACTION");

	return retval;
}

int rpc_send_fd(enum script_actions act, int fd)
{
	const char *action = action_names[act];

	if (scripts_mode != SCRIPTS_RPC)
		return -1;

	pr_debug("\tRPC\n");
	return send_criu_rpc_script(act, (char *)action, rpc_sk, fd);
}

int run_scripts(enum script_actions act)
{
	int ret = 0;
	const char *action = action_names[act];

	pr_debug("Running %s scripts\n", action);

	if (scripts_mode == SCRIPTS_NONE)
		return 0;

	if (scripts_mode == SCRIPTS_RPC) {
		pr_debug("\tRPC\n");
		ret = send_criu_rpc_script(act, (char *)action, rpc_sk, -1);
		goto out;
	}

	if (scripts_mode == SCRIPTS_SHELL) {
		ret = run_shell_scripts(action);
		goto out;
	}

	BUG();
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

	rpc_sk = install_service_fd(RPC_SK_OFF, sk);

	return 0;
}
