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

typedef struct {
	struct list_head head;
	struct list_head hook_chain[CR_PLUGIN_HOOK__MAX];
} cr_plugin_ctl_t;

extern cr_plugin_ctl_t cr_plugin_ctl;

typedef struct {
	cr_plugin_desc_t *d;
	struct list_head list;
	void *dlhandle;
	struct list_head link[CR_PLUGIN_HOOK__MAX];
} plugin_desc_t;

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

#endif
