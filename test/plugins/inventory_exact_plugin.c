#include <errno.h>

#include "criu-plugin.h"
#include "image.h"

#define INVENTORY_EXACT_LONG_NAME "inventory_exact_extra"

static int inventory_exact_plugin_init(int stage)
{
	if (stage != CR_PLUGIN_STAGE__RESTORE)
		return add_inventory_plugin(INVENTORY_EXACT_LONG_NAME);

	if (!has_inventory_plugin(INVENTORY_EXACT_LONG_NAME))
		return -EINVAL;
	if (has_inventory_plugin(CR_PLUGIN_DESC.name))
		return -EINVAL;
	if (check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name))
		return -EINVAL;

	return 0;
}

static void inventory_exact_plugin_fini(int stage, int ret)
{
}

CR_PLUGIN_REGISTER("inventory_exact", inventory_exact_plugin_init,
		   inventory_exact_plugin_fini)
