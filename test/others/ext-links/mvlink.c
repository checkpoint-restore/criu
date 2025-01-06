#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "criu-plugin.h"
#include "criu-log.h"

extern cr_plugin_init_t cr_plugin_init;
extern cr_plugin_dump_ext_link_t cr_plugin_dump_ext_link;

int cr_plugin_init(void)
{
	pr_info("Initialized macvlan dumper\n");
	return 0;
}

int cr_plugin_dump_ext_link(int index, int type, char *kind)
{
	if (strcmp(kind, "macvlan"))
		return -ENOTSUP;
	else {
		pr_info("Dump %d macvlan\n", index);
		return 0;
	}
}
