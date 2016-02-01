/*
 *  This file defines types and macros for CRIU plugins.
 *  Copyright (C) 2013-2014 Parallels, Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CRIU_PLUGIN_H__
#define __CRIU_PLUGIN_H__

#include <limits.h>
#include <stdbool.h>

#define CRIU_PLUGIN_GEN_VERSION(a,b,c)	(((a) << 16) + ((b) << 8) + (c))
#define CRIU_PLUGIN_VERSION_MAJOR	0
#define CRIU_PLUGIN_VERSION_MINOR	2
#define CRIU_PLUGIN_VERSION_SUBLEVEL	0

#define CRIU_PLUGIN_VERSION_OLD		CRIU_PLUGIN_GEN_VERSION(0,1,0)

#define CRIU_PLUGIN_VERSION					\
	CRIU_PLUGIN_GEN_VERSION(CRIU_PLUGIN_VERSION_MAJOR,	\
				CRIU_PLUGIN_VERSION_MINOR,	\
				CRIU_PLUGIN_VERSION_SUBLEVEL)

/*
 * Plugin hook points and their arguments in hooks.
 */
enum {
	CR_PLUGIN_HOOK__DUMP_UNIX_SK		= 0,
	CR_PLUGIN_HOOK__RESTORE_UNIX_SK		= 1,

	CR_PLUGIN_HOOK__DUMP_EXT_FILE		= 2,
	CR_PLUGIN_HOOK__RESTORE_EXT_FILE	= 3,

	CR_PLUGIN_HOOK__DUMP_EXT_MOUNT		= 4,
	CR_PLUGIN_HOOK__RESTORE_EXT_MOUNT	= 5,

	CR_PLUGIN_HOOK__DUMP_EXT_LINK		= 6,

	CR_PLUGIN_HOOK__MAX
};

#define DECLARE_PLUGIN_HOOK_ARGS(__hook, ...)	\
	typedef int (__hook ##_t)(__VA_ARGS__)

DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_UNIX_SK, int fd, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_UNIX_SK, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_FILE, int fd, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_MOUNT, char *mountpoint, int id);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__RESTORE_EXT_MOUNT, int id, char *mountpoint, char *old_root, int *is_file);
DECLARE_PLUGIN_HOOK_ARGS(CR_PLUGIN_HOOK__DUMP_EXT_LINK, int index, int type, char *kind);

enum {
	CR_PLUGIN_STAGE__DUMP,
	CR_PLUGIN_STAGE__PRE_DUMP,
	CR_PLUGIN_STAGE__RESTORE,

	CR_PLUGIN_STAGE_MAX
};

/*
 * Plugin descriptor.
 */
typedef struct {
	const char		*name;
	int			(*init)(int stage);
	void			(*exit)(int stage, int ret);
	unsigned int		version;
	unsigned int		max_hooks;
	void			*hooks[CR_PLUGIN_HOOK__MAX];
} cr_plugin_desc_t;

extern cr_plugin_desc_t CR_PLUGIN_DESC;

#define CR_PLUGIN_REGISTER(___name, ___init, ___exit)					\
	cr_plugin_desc_t CR_PLUGIN_DESC = {						\
		.name		= ___name,						\
		.init		= ___init,						\
		.exit		= ___exit,						\
		.version	= CRIU_PLUGIN_VERSION,					\
		.max_hooks	= CR_PLUGIN_HOOK__MAX,					\
	};

static inline int cr_plugin_dummy_init(int stage) { return 0; }
static inline void cr_plugin_dummy_exit(int stage, int ret) { }

#define CR_PLUGIN_REGISTER_DUMMY(___name)						\
	cr_plugin_desc_t CR_PLUGIN_DESC = {						\
		.name		= ___name,						\
		.init		= cr_plugin_dummy_init,					\
		.exit		= cr_plugin_dummy_exit,					\
		.version	= CRIU_PLUGIN_VERSION,					\
		.max_hooks	= CR_PLUGIN_HOOK__MAX,					\
	};

#define CR_PLUGIN_REGISTER_HOOK(__hook, __func)						\
static void __attribute__((constructor)) cr_plugin_register_hook_##__func (void)	\
{											\
	CR_PLUGIN_DESC.hooks[__hook] = (void *)__func;					\
}

/* Public API */
extern int criu_get_image_dir(void);

/*
 * Deprecated, will be removed in next version.
 */
typedef int (cr_plugin_init_t)(void);
typedef void (cr_plugin_fini_t)(void);
typedef int (cr_plugin_dump_unix_sk_t)(int fd, int id);
typedef int (cr_plugin_restore_unix_sk_t)(int id);
typedef int (cr_plugin_dump_file_t)(int fd, int id);
typedef int (cr_plugin_restore_file_t)(int id);
typedef int (cr_plugin_dump_ext_mount_t)(char *mountpoint, int id);
typedef int (cr_plugin_restore_ext_mount_t)(int id, char *mountpoint, char *old_root, int *is_file);
typedef int (cr_plugin_dump_ext_link_t)(int index, int type, char *kind);

#endif /* __CRIU_PLUGIN_H__ */
