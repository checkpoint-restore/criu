#ifndef __CR_PLUGIN_H__
#define __CR_PLUGIN_H__

#include "criu-plugin.h"

#define CR_PLUGIN_DEFAULT "/var/lib/criu/"

void cr_plugin_fini(void);
int cr_plugin_init(void);

int cr_plugin_dump_unix_sk(int fd, int id);
int cr_plugin_restore_unix_sk(int id);

#endif
