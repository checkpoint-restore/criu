#include "criu-plugin.h"
#include "image.h"

int inventory_test_disabled_plugin_init(int stage)
{
	if (stage == CR_PLUGIN_STAGE__RESTORE)
		return check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name, strlen(CR_PLUGIN_DESC.name));

	return 0;
}

void inventory_test_disabled_plugin_fini(int stage, int ret)
{
	return;
}

CR_PLUGIN_REGISTER("inventory_test_disabled_plugin", inventory_test_disabled_plugin_init, inventory_test_disabled_plugin_fini)