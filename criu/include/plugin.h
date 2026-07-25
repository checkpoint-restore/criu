#ifndef __CR_PLUGIN_H__
#define __CR_PLUGIN_H__

#include "criu-plugin.h"
#include "common/compiler.h"
#include "common/list.h"

#ifndef CR_PLUGIN_DEFAULT
#define CR_PLUGIN_DEFAULT "/usr/lib/criu/"
#endif

void cr_plugin_fini(int stage, int err);
int cr_plugin_init(int stage);
int cr_plugin_option_add(const char *plugin, const char *name, const char *value);
int cr_plugin_option_add_arg(const char *arg);
void cr_plugin_options_clear(void);

typedef struct {
	struct list_head head;
	struct list_head hook_chain[CR_PLUGIN_HOOK__MAX];
} cr_plugin_ctl_t;

extern cr_plugin_ctl_t cr_plugin_ctl;

typedef struct {
	cr_plugin_desc_t *d;
	unsigned int implementation_version;
	struct list_head list;
	void *dlhandle;
	struct list_head link[CR_PLUGIN_HOOK__MAX];
	bool initialized;
} plugin_desc_t;

static inline unsigned int cr_plugin_implementation_version(const cr_plugin_desc_t *d)
{
	if (d->implementation_version)
		return d->implementation_version;

	/*
	 * Descriptors from older plugins leave this field unset.
	 * We assume an unset field as v1 to preserve compatibility.
	 */
	return CR_PLUGIN_IMPLEMENTATION_VERSION_DEFAULT;
}

static inline bool cr_plugin_names_equal(const char *left, const char *right)
{
	while (*left && *left == *right) {
		left++;
		right++;
	}

	return *left == *right;
}

static inline plugin_desc_t *cr_plugin_find_in_list(struct list_head *head, const char *name,
						    unsigned int implementation_version)
{
	plugin_desc_t *plugin;

	list_for_each_entry(plugin, head, list) {
		if (plugin->implementation_version == implementation_version && cr_plugin_names_equal(plugin->d->name, name))
			return plugin;
	}

	return NULL;
}

static inline plugin_desc_t *
cr_plugin_find_latest_in_list(struct list_head *head, const char *name)
{
	plugin_desc_t *plugin;
	plugin_desc_t *latest = NULL;

	list_for_each_entry(plugin, head, list) {
		if (!cr_plugin_names_equal(plugin->d->name, name))
			continue;

		if (!latest ||
		    plugin->implementation_version > latest->implementation_version)
			latest = plugin;
	}

	return latest;
}

plugin_desc_t *cr_plugin_find(const char *name, unsigned int implementation_version);

#define run_plugins(__hook, ...)                                                                            \
	({                                                                                                  \
		plugin_desc_t *this;                                                                        \
		int __ret = -ENOTSUP;                                                                       \
                                                                                                            \
		list_for_each_entry(this, &cr_plugin_ctl.hook_chain[CR_PLUGIN_HOOK__##__hook],              \
				    link[CR_PLUGIN_HOOK__##__hook]) {                                       \
			pr_debug("plugin: `%s' hook %u -> %p\n", this->d->name, CR_PLUGIN_HOOK__##__hook,   \
				 this->d->hooks[CR_PLUGIN_HOOK__##__hook]);                                 \
			__ret = ((CR_PLUGIN_HOOK__##__hook##_t *)this->d->hooks[CR_PLUGIN_HOOK__##__hook])( \
				__VA_ARGS__);                                                               \
			if (__ret == -ENOTSUP)                                                              \
				continue;                                                                   \
			break;                                                                              \
		}                                                                                           \
		__ret;                                                                                      \
	})

#define run_plugins_all(__hook, ...)                                                                        \
	({                                                                                                  \
		plugin_desc_t *this;                                                                        \
		bool __handled = false;                                                                     \
		int __ret = 0;                                                                              \
                                                                                                            \
		list_for_each_entry(this, &cr_plugin_ctl.hook_chain[CR_PLUGIN_HOOK__##__hook],              \
				    link[CR_PLUGIN_HOOK__##__hook]) {                                       \
			int __hook_ret;                                                                     \
                                                                                                            \
			pr_debug("plugin: `%s' hook %u -> %p\n", this->d->name, CR_PLUGIN_HOOK__##__hook,   \
				 this->d->hooks[CR_PLUGIN_HOOK__##__hook]);                                 \
			__hook_ret =                                                                         \
				((CR_PLUGIN_HOOK__##__hook##_t *)this->d->hooks[CR_PLUGIN_HOOK__##__hook])( \
					__VA_ARGS__);                                                        \
			if (__hook_ret == -ENOTSUP)                                                         \
				continue;                                                                   \
			__handled = true;                                                                   \
			if (__hook_ret && !__ret)                                                           \
				__ret = __hook_ret;                                                         \
		}                                                                                           \
		__handled ? __ret : -ENOTSUP;                                                               \
	})

#endif
