#include <errno.h>
#include <string.h>

#include "cr_options.h"
#include "common/list.h"
#include "common/xmalloc.h"
#include "log.h"
#include "plugin.h"

static void cr_plugin_option_free(struct cr_plugin_option *option)
{
	list_del(&option->node);
	xfree(option->plugin);
	xfree(option->name);
	xfree(option->value);
	xfree(option);
}

void cr_plugin_options_clear(void)
{
	struct cr_plugin_option *option, *tmp;

	list_for_each_entry_safe(option, tmp, &opts.plugin_options, node)
		cr_plugin_option_free(option);
}

int cr_plugin_option_add(const char *plugin, const char *name, const char *value)
{
	struct cr_plugin_option *option;

	if (!plugin || !plugin[0] || !name || !name[0] || !value)
		return -EINVAL;

	option = xzalloc(sizeof(*option));
	if (!option)
		return -ENOMEM;

	option->plugin = xstrdup(plugin);
	option->name = xstrdup(name);
	option->value = xstrdup(value);
	if (!option->plugin || !option->name || !option->value) {
		xfree(option->plugin);
		xfree(option->name);
		xfree(option->value);
		xfree(option);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&option->node);
	list_add_tail(&option->node, &opts.plugin_options);
	return 0;
}

int cr_plugin_option_add_arg(const char *arg)
{
	const char *dot, *equal;
	char *plugin = NULL;
	char *name = NULL;
	int ret;

	if (!arg) {
		pr_err("Plugin option is missing\n");
		return -EINVAL;
	}

	dot = strchr(arg, '.');
	equal = strchr(arg, '=');
	if (!dot || !equal || dot == arg || equal <= dot + 1 || equal < dot) {
		pr_err("Invalid plugin option '%s' (expected PLUGIN.NAME=VALUE)\n", arg);
		return -EINVAL;
	}

	plugin = xmalloc((size_t)(dot - arg) + 1);
	name = xmalloc((size_t)(equal - dot - 1) + 1);
	if (!plugin || !name) {
		xfree(plugin);
		xfree(name);
		return -ENOMEM;
	}

	memcpy(plugin, arg, (size_t)(dot - arg));
	plugin[dot - arg] = '\0';
	memcpy(name, dot + 1, (size_t)(equal - dot - 1));
	name[equal - dot - 1] = '\0';

	ret = cr_plugin_option_add(plugin, name, equal + 1);
	xfree(plugin);
	xfree(name);
	return ret;
}

int criu_plugin_get_option(const char *plugin, const char *name, const char **value)
{
	struct cr_plugin_option *option;

	if (!plugin || !plugin[0] || !name || !name[0] || !value)
		return -EINVAL;

	*value = NULL;
	list_for_each_entry_reverse(option, &opts.plugin_options, node) {
		if (strcmp(option->plugin, plugin) || strcmp(option->name, name))
			continue;

		*value = option->value;
		return 0;
	}

	return -ENOENT;
}
