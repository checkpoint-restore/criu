#include <stdio.h>

#include "criu-plugin.h"

static int print_help(void)
{
	puts("Second plugin help");
	return 0;
}

CR_PLUGIN_REGISTER_DUMMY("test-help-plugin")
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PRINT_HELP, print_help)
