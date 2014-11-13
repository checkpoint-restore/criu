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

static const char *action_names[ACT_MAX] = {
	[ ACT_POST_DUMP ]	= "post-dump",
	[ ACT_POST_RESTORE ]	= "post-restore",
	[ ACT_NET_LOCK ]	= "network-lock",
	[ ACT_NET_UNLOCK ]	= "network-unlock",
	[ ACT_SETUP_NS ]	= "setup-namespaces",
};

int run_scripts(enum script_actions act)
{
	struct script *script;
	int ret = 0;
	char image_dir[PATH_MAX];
	const char *action = action_names[act];

	pr_debug("Running %s scripts\n", action);

	if (unlikely(list_empty(&opts.scripts)))
		return 0;

	if (setenv("CRTOOLS_SCRIPT_ACTION", action, 1)) {
		pr_perror("Can't set CRTOOLS_SCRIPT_ACTION=%s", action);
		return -1;
	}

	sprintf(image_dir, "/proc/%ld/fd/%d", (long) getpid(), get_service_fd(IMG_FD_OFF));
	if (setenv("CRTOOLS_IMAGE_DIR", image_dir, 1)) {
		pr_perror("Can't set CRTOOLS_IMAGE_DIR=%s", image_dir);
		return -1;
	}

	list_for_each_entry(script, &opts.scripts, node) {
		if (script->path == SCRIPT_RPC_NOTIFY) {
			pr_debug("\tRPC\n");
			ret |= send_criu_rpc_script(act, (char *)action, script->arg);
		} else {
			pr_debug("\t[%s]\n", script->path);
			ret |= system(script->path);
		}
	}

	unsetenv("CRTOOLS_SCRIPT_ACTION");
	return ret;
}

int add_script(char *path, int arg)
{
	struct script *script;

	script = xmalloc(sizeof(struct script));
	if (script == NULL)
		return 1;

	script->path = path;
	script->arg = arg;
	list_add(&script->node, &opts.scripts);

	return 0;
}
