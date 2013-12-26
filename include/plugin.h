#ifndef __CR_PLUGIN_H__
#define __CR_PLUGIN_H__

#include "criu-plugin.h"

#define CR_PLUGIN_DEFAULT "/var/lib/criu/"

void cr_plugin_fini(void);
int cr_plugin_init(void);

int cr_plugin_dump_unix_sk(int fd, int id);
int cr_plugin_restore_unix_sk(int id);

int cr_plugin_dump_file(int fd, int id);
int cr_plugin_restore_file(int id);

int cr_plugin_dump_ext_mount(char *mountpoint, int id);
int cr_plugin_restore_ext_mount(int id, char *mountpoint, char *old_root, int *is_file);

int cr_plugin_dump_ext_link(int index, int type, char *kind);

#endif
