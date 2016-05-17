#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

#include "cr_options.h"
#include "compiler.h"
#include "xmalloc.h"
#include "plugin.h"
#include "list.h"
#include "log.h"

cr_plugin_ctl_t cr_plugin_ctl = {
	.head.next = &cr_plugin_ctl.head,
	.head.prev = &cr_plugin_ctl.head,
};

/*
 * If we met old version of a plugin, selfgenerate a plugin descriptor for it.
 */
static cr_plugin_desc_t *cr_gen_plugin_desc(void *h, char *path)
{
	cr_plugin_desc_t *d;

	d = xzalloc(sizeof(*d));
	if (!d)
		return NULL;

	d->name		= strdup(path);
	d->max_hooks	= CR_PLUGIN_HOOK__MAX;
	d->version	= CRIU_PLUGIN_VERSION_OLD;

	pr_warn("Generating dynamic descriptor for plugin `%s'."
		"Won't work in next version of the program."
		"Please update your plugin.\n", path);

#define __assign_hook(__hook, __name)					\
	do {								\
		void *name;						\
		name = dlsym(h, __name);				\
		if (name)						\
			d->hooks[CR_PLUGIN_HOOK__ ##__hook] = name;	\
	} while (0)

	__assign_hook(DUMP_UNIX_SK,		"cr_plugin_dump_unix_sk");
	__assign_hook(RESTORE_UNIX_SK,		"cr_plugin_restore_unix_sk");
	__assign_hook(DUMP_EXT_FILE,		"cr_plugin_dump_file");
	__assign_hook(RESTORE_EXT_FILE,		"cr_plugin_restore_file");
	__assign_hook(DUMP_EXT_MOUNT,		"cr_plugin_dump_ext_mount");
	__assign_hook(RESTORE_EXT_MOUNT,	"cr_plugin_restore_ext_mount");
	__assign_hook(DUMP_EXT_LINK,		"cr_plugin_dump_ext_link");

#undef __assign_hook

	d->init = dlsym(h, "cr_plugin_init");
	d->exit = dlsym(h, "cr_plugin_fini");

	return d;
}

static void show_plugin_desc(cr_plugin_desc_t *d)
{
	size_t i;

	pr_debug("Plugin \"%s\" (version %u hooks %u)\n",
		 d->name, d->version, d->max_hooks);
	for (i = 0; i < d->max_hooks; i++) {
		if (d->hooks[i])
			pr_debug("\t%4zu -> %p\n", i, d->hooks[i]);
	}
}

static int verify_plugin(cr_plugin_desc_t *d)
{
	if (d->version > CRIU_PLUGIN_VERSION) {
		pr_debug("Plugin %s has version %x while max %x supported\n",
			 d->name, d->version, CRIU_PLUGIN_VERSION);
		return -1;
	}

	if (d->max_hooks > CR_PLUGIN_HOOK__MAX) {
		pr_debug("Plugin %s has %u assigned while max %u supported\n",
			 d->name, d->max_hooks, CR_PLUGIN_HOOK__MAX);
		return -1;
	}

	return 0;
}

static int cr_lib_load(int stage, char *path)
{
	cr_plugin_desc_t *d;
	plugin_desc_t *this;
	size_t i;
	void *h;

	h = dlopen(path, RTLD_LAZY);
	if (h == NULL) {
		pr_err("Unable to load %s: %s\n", path, dlerror());
		return -1;
	}

	/*
	 * Load plugin descriptor. If plugin is too old -- create
	 * dynamic plugin descriptor. In most cases this won't
	 * be a common operation and plugins are not supposed to
	 * be changing own format frequently.
	 */
	d = dlsym(h, "CR_PLUGIN_DESC");
	if (!d)
		d = cr_gen_plugin_desc(h, path);
	if (!d) {
		pr_err("Can't load plugin %s\n", path);
		dlclose(h);
		return -1;
	}

	this = xzalloc(sizeof(*this));
	if (!this) {
		dlclose(h);
		return -1;
	}

	if (verify_plugin(d)) {
		pr_err("Corrupted plugin %s\n", path);
		xfree(this);
		dlclose(h);
		return -1;
	}

	this->d = d;
	this->dlhandle = h;
	INIT_LIST_HEAD(&this->list);

	for (i = 0; i < d->max_hooks; i++)
		INIT_LIST_HEAD(&this->link[i]);

	list_add_tail(&this->list, &cr_plugin_ctl.head);
	show_plugin_desc(d);

	if (d->init && d->init(stage)) {
		pr_err("Failed in init(%d) of \"%s\"\n", stage, d->name);
		list_del(&this->list);
		xfree(this);
		dlclose(h);
		return -1;
	}

	/*
	 * Chain hooks into appropriate places for
	 * fast handler access.
	 */
	for (i = 0; i < d->max_hooks; i++) {
		if (!d->hooks[i])
			continue;
		list_add_tail(&this->link[i], &cr_plugin_ctl.hook_chain[i]);
	}

	return 0;
}

void cr_plugin_fini(int stage, int ret)
{
	plugin_desc_t *this, *tmp;

	list_for_each_entry_safe(this, tmp, &cr_plugin_ctl.head, list) {
		void *h = this->dlhandle;
		size_t i;

		list_del(&this->list);
		if (this->d->exit)
			this->d->exit(stage, ret);

		for (i = 0; i < this->d->max_hooks; i++) {
			if (!list_empty(&this->link[i]))
				list_del(&this->link[i]);
		}

		if (this->d->version == CRIU_PLUGIN_VERSION_OLD)
			xfree(this->d);
		dlclose(h);
	}
}

int cr_plugin_init(int stage)
{
	int exit_code = -1;
	char *path;
	size_t i;
	DIR *d;

	INIT_LIST_HEAD(&cr_plugin_ctl.head);
	for (i = 0; i < ARRAY_SIZE(cr_plugin_ctl.hook_chain); i++)
		INIT_LIST_HEAD(&cr_plugin_ctl.hook_chain[i]);

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

		if (cr_lib_load(stage, path))
			goto err;
	}

	exit_code = 0;
err:
	closedir(d);

	if (exit_code)
		cr_plugin_fini(stage, exit_code);

	return exit_code;
}
