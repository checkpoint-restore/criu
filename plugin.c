#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include "cr_options.h"
#include "plugin.h"
#include "log.h"
#include "xmalloc.h"

struct cr_plugin_entry {
	union {
		cr_plugin_fini_t *cr_fini;

		cr_plugin_dump_unix_sk_t *cr_plugin_dump_unix_sk;
		cr_plugin_restore_unix_sk_t *cr_plugin_restore_unix_sk;
		cr_plugin_dump_file_t *cr_plugin_dump_file;
		cr_plugin_restore_file_t *cr_plugin_restore_file;
		cr_plugin_dump_ext_mount_t *cr_plugin_dump_ext_mount;
		cr_plugin_restore_ext_mount_t *cr_plugin_restore_ext_mount;
		cr_plugin_dump_ext_link_t *cr_plugin_dump_ext_link;
	};

	struct cr_plugin_entry *next;
};

struct cr_plugins {
	struct cr_plugin_entry *cr_fini;

	struct cr_plugin_entry *cr_plugin_dump_unix_sk;
	struct cr_plugin_entry *cr_plugin_restore_unix_sk;
	struct cr_plugin_entry *cr_plugin_dump_file;
	struct cr_plugin_entry *cr_plugin_restore_file;
	struct cr_plugin_entry *cr_plugin_dump_ext_mount;
	struct cr_plugin_entry *cr_plugin_restore_ext_mount;
	struct cr_plugin_entry *cr_plugin_dump_ext_link;
};

struct cr_plugins cr_plugins;

#define add_plugin_func(name)						\
	do {								\
		name ## _t *name;					\
		name = dlsym(h, #name);					\
		if (name) {						\
			struct cr_plugin_entry *__ce;			\
			__ce = xmalloc(sizeof(struct cr_plugin_entry));	\
			if (__ce == NULL)				\
				goto nomem;				\
			__ce->name = name;				\
			__ce->next = cr_plugins.name;			\
			cr_plugins.name = __ce;				\
		}							\
	} while (0);							\


#define run_plugin_funcs(name, ...) ({					\
		struct cr_plugin_entry *__ce = cr_plugins.name;		\
		int __ret = -ENOTSUP;					\
									\
		while (__ce) {						\
			__ret = __ce->name(__VA_ARGS__);		\
			if (__ret == -ENOTSUP) {			\
				__ce = __ce->next;			\
				continue;				\
			}						\
			break;						\
		}							\
									\
		__ret;							\
	})								\

int cr_plugin_dump_unix_sk(int fd, int id)
{
	return run_plugin_funcs(cr_plugin_dump_unix_sk, fd, id);
}

int cr_plugin_restore_unix_sk(int id)
{
	return run_plugin_funcs(cr_plugin_restore_unix_sk, id);
}

int cr_plugin_dump_file(int fd, int id)
{
	return run_plugin_funcs(cr_plugin_dump_file, fd, id);
}

int cr_plugin_restore_file(int id)
{
	return run_plugin_funcs(cr_plugin_restore_file, id);
}

int cr_plugin_dump_ext_mount(char *mountpoint, int id)
{
	return run_plugin_funcs(cr_plugin_dump_ext_mount, mountpoint, id);
}

int cr_plugin_restore_ext_mount(int id, char *mountpoint, char *old_root, int *is_file)
{
	return run_plugin_funcs(cr_plugin_restore_ext_mount, id, mountpoint, old_root, is_file);
}

int cr_plugin_dump_ext_link(int index, int type, char *kind)
{
	return run_plugin_funcs(cr_plugin_dump_ext_link, index, type, kind);
}

static int cr_lib_load(char *path)
{
	struct cr_plugin_entry *ce;
	cr_plugin_init_t *f_init;
	cr_plugin_fini_t *f_fini;
	void *h;

	h = dlopen(path, RTLD_LAZY);
	if (h == NULL) {
		pr_err("Unable to load %s: %s", path, dlerror());
		return -1;
	}

	add_plugin_func(cr_plugin_dump_unix_sk);
	add_plugin_func(cr_plugin_restore_unix_sk);

	add_plugin_func(cr_plugin_dump_file);
	add_plugin_func(cr_plugin_restore_file);

	add_plugin_func(cr_plugin_dump_ext_mount);
	add_plugin_func(cr_plugin_restore_ext_mount);

	add_plugin_func(cr_plugin_dump_ext_link);

	ce = NULL;
	f_fini = dlsym(h, "cr_plugin_fini");
	if (f_fini) {
		ce = xmalloc(sizeof(struct cr_plugin_entry));
		if (ce == NULL)
			goto nomem;
		ce->cr_fini = f_fini;
	}

	f_init = dlsym(h, "cr_plugin_init");
	if (f_init && f_init()) {
		xfree(ce);
		return -1;
	}

	if (ce) {
		ce->next = cr_plugins.cr_fini;
		cr_plugins.cr_fini = ce;
	}

	return 0;

nomem:
	return -1;
}

#define cr_plugin_free(name) do {				\
	while (cr_plugins.name) {				\
		ce = cr_plugins.name;				\
		cr_plugins.name = cr_plugins.name->next;	\
		xfree(ce);					\
	}							\
} while (0)							\

void cr_plugin_fini(void)
{
	struct cr_plugin_entry *ce;

	cr_plugin_free(cr_plugin_dump_unix_sk);
	cr_plugin_free(cr_plugin_restore_unix_sk);

	cr_plugin_free(cr_plugin_dump_file);
	cr_plugin_free(cr_plugin_restore_file);

	while (cr_plugins.cr_fini) {
		ce = cr_plugins.cr_fini;
		cr_plugins.cr_fini = cr_plugins.cr_fini->next;

		ce->cr_fini();
		xfree(ce);
	}
}

int cr_plugin_init(void)
{
	int exit_code = -1;
	char *path;
	DIR *d;

	memset(&cr_plugins, 0, sizeof(cr_plugins));

	if (opts.libdir == NULL) {
		path = getenv("CRIU_LIBS_DIR");
		if (path)
			opts.libdir = path;
		else {
			if (access(CR_PLUGIN_DEFAULT, F_OK))
				return 0;

			opts.libdir = CR_PLUGIN_DEFAULT;
		}
	}

	d = opendir(opts.libdir);
	if (d == NULL) {
		pr_perror("Unable to open directory %s", opts.libdir);
		return -1;
	}

	while (1) {
		char path[PATH_MAX];
		struct dirent *de;
		int len;

		errno = 0;
		de = readdir(d);
		if (de == NULL) {
			if (errno == 0)
				break;
			pr_perror("Unable to read the libraries directory");
			goto err;
		}

		len = strlen(de->d_name);

		if (len < 3 || strncmp(de->d_name + len - 3, ".so", 3))
			continue;

		snprintf(path, sizeof(path), "%s/%s", opts.libdir, de->d_name);

		if (cr_lib_load(path))
			goto err;
	}

	exit_code = 0;
err:
	closedir(d);

	if (exit_code)
		cr_plugin_fini();

	return exit_code;
}
