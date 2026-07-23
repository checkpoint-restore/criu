#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <stddef.h>

#include "cr_options.h"
#include "common/compiler.h"
#include "xmalloc.h"
#include "plugin.h"
#include "servicefd.h"
#include "common/list.h"
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

	d->name = xstrdup(path);
	d->max_hooks = CR_PLUGIN_HOOK__MAX;
	d->version = CRIU_PLUGIN_VERSION_OLD;
	d->implementation_version = CR_PLUGIN_IMPLEMENTATION_VERSION_DEFAULT;

	pr_warn("Generating dynamic descriptor for plugin `%s'."
		"Won't work in next version of the program."
		"Please update your plugin.\n",
		path);

#define __assign_hook(__hook, __name)                              \
	do {                                                       \
		void *name;                                        \
		name = dlsym(h, __name);                           \
		if (name)                                          \
			d->hooks[CR_PLUGIN_HOOK__##__hook] = name; \
	} while (0)

	__assign_hook(DUMP_UNIX_SK, "cr_plugin_dump_unix_sk");
	__assign_hook(RESTORE_UNIX_SK, "cr_plugin_restore_unix_sk");
	__assign_hook(DUMP_EXT_FILE, "cr_plugin_dump_file");
	__assign_hook(RESTORE_EXT_FILE, "cr_plugin_restore_file");
	__assign_hook(DUMP_EXT_MOUNT, "cr_plugin_dump_ext_mount");
	__assign_hook(RESTORE_EXT_MOUNT, "cr_plugin_restore_ext_mount");
	__assign_hook(DUMP_EXT_LINK, "cr_plugin_dump_ext_link");
	__assign_hook(HANDLE_DEVICE_VMA, "cr_plugin_handle_device_vma");
	__assign_hook(UPDATE_VMA_MAP, "cr_plugin_update_vma_map");
	__assign_hook(RESUME_DEVICES_LATE, "cr_plugin_resume_devices_late");
	__assign_hook(PAUSE_DEVICES, "cr_plugin_pause_devices");
	__assign_hook(CHECKPOINT_DEVICES, "cr_plugin_checkpoint_devices");
	__assign_hook(POST_FORKING, "cr_plugin_post_forking");
	__assign_hook(RESTORE_INIT, "cr_plugin_restore_init");
	__assign_hook(DUMP_DEVICES_LATE, "cr_plugin_dump_devices_late");
	__assign_hook(UPDATE_INETSK, "cr_plugin_update_inetsk");

#undef __assign_hook

	d->init = dlsym(h, "cr_plugin_init");
	d->exit = dlsym(h, "cr_plugin_fini");

	return d;
}

static void show_plugin_desc(const plugin_desc_t *plugin)
{
	size_t i;
	cr_plugin_desc_t *d = plugin->d;

	pr_debug("Plugin \"%s\" (API version %u, implementation version %u, hooks %u)\n",
		d->name, d->version, plugin->implementation_version, d->max_hooks);
	for (i = 0; i < d->max_hooks; i++) {
		if (d->hooks[i])
			pr_debug("\t%4zu -> %p\n", i, d->hooks[i]);
	}
}

static bool cr_plugin_has_implementation_version(void *h, cr_plugin_desc_t *d)
{
	const unsigned int *desc_size;
	size_t required_size;

	required_size = offsetof(cr_plugin_desc_t, implementation_version);
	required_size += sizeof(d->implementation_version);

	/*
	 * Plugins built before implementation versions were added do not export
	 * CR_PLUGIN_DESC_SIZE and therefore have no field that can be read safely.
	 */
	desc_size = dlsym(h, "CR_PLUGIN_DESC_SIZE");

	return desc_size && *desc_size >= required_size;
}

static unsigned int cr_plugin_get_implementation_version(void *h, cr_plugin_desc_t *d)
{
	if (!cr_plugin_has_implementation_version(h, d))
		return CR_PLUGIN_IMPLEMENTATION_VERSION_DEFAULT;

	return cr_plugin_implementation_version(d);
}

plugin_desc_t *cr_plugin_find(const char *name, unsigned int implementation_version)
{
	return cr_plugin_find_in_list(&cr_plugin_ctl.head, name, implementation_version);
}

static int verify_plugin(cr_plugin_desc_t *d)
{
	if (d->version > CRIU_PLUGIN_VERSION) {
		pr_debug("Plugin %s has version %x while max %x supported\n", d->name, d->version, CRIU_PLUGIN_VERSION);
		return -1;
	}

	if (d->max_hooks > CR_PLUGIN_HOOK__MAX) {
		pr_debug("Plugin %s has %u assigned while max %u supported\n", d->name, d->max_hooks,
			 CR_PLUGIN_HOOK__MAX);
		return -1;
	}

	return 0;
}

int criu_get_image_dir(void)
{
	return get_service_fd(IMG_FD_OFF);
}

static int cr_lib_load(char *path)
{
	cr_plugin_desc_t *d;
	plugin_desc_t *this;
	size_t i;
	void *h;
	bool allocated = false;

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
	if (!d) {
		d = cr_gen_plugin_desc(h, path);
		if (!d) {
			pr_err("Can't load plugin %s\n", path);
			goto error_close;
		}
		allocated = true;
	}

	this = xzalloc(sizeof(*this));
	if (!this)
		goto error_close;

	if (verify_plugin(d)) {
		pr_err("Corrupted plugin %s\n", path);
		goto error_free;
	}

	this->d = d;
	this->implementation_version = cr_plugin_get_implementation_version(h, d);
	this->dlhandle = h;
	INIT_LIST_HEAD(&this->list);

	if (cr_plugin_find(d->name, this->implementation_version)) {
		pr_err("Plugin %s implementation version %u is already loaded\n", d->name, this->implementation_version);
		goto error_free;
	}

	for (i = 0; i < d->max_hooks; i++)
		INIT_LIST_HEAD(&this->link[i]);

	list_add_tail(&this->list, &cr_plugin_ctl.head);

	return 0;

error_free:
	xfree(this);
error_close:
	dlclose(h);
	if (allocated)
		xfree(d);
	return -1;
}

static void cr_plugin_unload(plugin_desc_t *plugin, int stage, int ret)
{
	size_t i;

	list_del(&plugin->list);

	if (plugin->initialized && plugin->d->exit)
		plugin->d->exit(stage, ret);

	for (i = 0; i < plugin->d->max_hooks; i++) {
		if (!list_empty(&plugin->link[i]))
			list_del(&plugin->link[i]);
	}

	if (plugin->d->version == CRIU_PLUGIN_VERSION_OLD)
		xfree(plugin->d);
	dlclose(plugin->dlhandle);
	xfree(plugin);
}

static void cr_plugin_select_versions(void)
{
	plugin_desc_t *plugin, *tmp, *latest;

	list_for_each_entry_safe(plugin, tmp, &cr_plugin_ctl.head, list) {
		latest = cr_plugin_find_latest_in_list(&cr_plugin_ctl.head, plugin->d->name);
		if (latest == plugin)
			continue;

		pr_debug("Skipping plugin %s implementation version %u; "
			 "version %u is newer\n",
			 plugin->d->name, plugin->implementation_version,
			 latest->implementation_version);
		cr_plugin_unload(plugin, 0, 0);
	}
}

static int cr_plugin_activate(int stage)
{
	plugin_desc_t *plugin;
	size_t i;

	list_for_each_entry(plugin, &cr_plugin_ctl.head, list) {
		show_plugin_desc(plugin);

		if (plugin->d->init && plugin->d->init(stage)) {
			pr_err("Failed in init(%d) of \"%s\"\n", stage, plugin->d->name);
			return -1;
		}
		plugin->initialized = true;

		/*
		 * Chain hooks into appropriate places for
		 * fast handler access.
		 */
		for (i = 0; i < plugin->d->max_hooks; i++) {
			if (!plugin->d->hooks[i])
				continue;
			list_add_tail(&plugin->link[i], &cr_plugin_ctl.hook_chain[i]);
		}
	}

	return 0;
}

void cr_plugin_fini(int stage, int ret)
{
	plugin_desc_t *this, *tmp;

	list_for_each_entry_safe(this, tmp, &cr_plugin_ctl.head, list) {
		cr_plugin_unload(this, stage, ret);
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
			SET_CHAR_OPTS(libdir, path);
		else {
			if (access(CR_PLUGIN_DEFAULT, F_OK))
				return 0;

			SET_CHAR_OPTS(libdir, CR_PLUGIN_DEFAULT);
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

		if (snprintf(path, sizeof(path), "%s/%s", opts.libdir, de->d_name) >= sizeof(path)) {
			pr_err("Unable to build plugin path\n");
			goto err;
		}

		if (cr_lib_load(path))
			goto err;
	}

	/* Select implementations before calling init or registering hooks. */
	cr_plugin_select_versions();
	if (cr_plugin_activate(stage))
		goto err;

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		int ret;

		if (check_inventory_plugins())
			goto err;

		ret = run_plugins(RESTORE_INIT);
		if (ret < 0 && ret != -ENOTSUP)
			goto err;
	}

	exit_code = 0;
err:
	closedir(d);

	if (exit_code)
		cr_plugin_fini(stage, exit_code);

	return exit_code;
}
