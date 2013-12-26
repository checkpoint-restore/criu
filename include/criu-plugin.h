/*
    This file defines types and macros for CRIU plugins.
    Copyright (C) 2013 Parallels, Inc

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CRIU_PLUGIN_H__
#define __CRIU_PLUGIN_H__

#include <limits.h>
#include <stdbool.h>

typedef int (cr_plugin_init_t)(void);
typedef void (cr_plugin_fini_t)(void);

typedef int (cr_plugin_dump_unix_sk_t)(int fd, int id);
typedef int (cr_plugin_restore_unix_sk_t)(int id);

typedef int (cr_plugin_dump_file_t)(int fd, int id);
typedef int (cr_plugin_restore_file_t)(int id);

typedef int (cr_plugin_dump_ext_mount_t)(char *mountpoint, int id);
typedef int (cr_plugin_restore_ext_mount_t)(int id, char *mountpoint, char *old_root, int *is_file);

typedef int (cr_plugin_dump_ext_link_t)(int index, int type, char *kind);

/* Public API */
extern int criu_get_image_dir(void);

#endif
