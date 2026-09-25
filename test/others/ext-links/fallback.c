#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

#include "criu-plugin.h"
#include "criu-log.h"

static int dump_ext_link(int index, int type, char *kind)
{
	const char *target = getenv("CRIU_FALLBACK_NAME");
	const char *mode = getenv("CRIU_FALLBACK_MODE");
	char name[IF_NAMESIZE];

	if (!target || !mode)
		return -EINVAL;
	if (!if_indextoname(index, name))
		return -errno;

	/* Accept other external links, including an auto-created erspan0. */
	if (strcmp(name, target))
		return 0;

	pr_info("fallback-test: %s %s %s\n", name, kind, mode);
	if (!strcmp(mode, "accept"))
		return 0;
	if (!strcmp(mode, "decline"))
		return -ENOTSUP;
	return -EIO;
}

CR_PLUGIN_REGISTER_DUMMY("fallback-test")
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_LINK, dump_ext_link)
