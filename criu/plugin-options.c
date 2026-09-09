#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cr_options.h"
#include "common/xmalloc.h"
#include "log.h"
#include "plugin.h"

static char *plugin_argv0 = "criu-plugin";

int cr_plugin_options_init(void)
{
	opts.plugin_options_default_n = 1;
	opts.plugin_options_n = 1;
	opts.plugin_options_max = 2;
	opts.plugin_options = xmalloc(sizeof(opts.plugin_options[0]) * opts.plugin_options_max);
	if (!opts.plugin_options)
		return -1;
	opts.plugin_options[0] = plugin_argv0;
	opts.plugin_options[1] = NULL;
	return 0;
}

void cr_plugin_default_options_parsed(void)
{
	opts.plugin_options_default_n = opts.plugin_options_n;
}

void cr_plugin_options_clear(void)
{
	int i;

	for (i = 1; i < opts.plugin_options_n; i++)
		xfree(opts.plugin_options[i]);

	opts.plugin_options_default_n = 1;
	opts.plugin_options_n = 1;
	opts.plugin_options[opts.plugin_options_n] = NULL;
}

void cr_plugin_options_clear_request(void)
{
	int i;

	for (i = opts.plugin_options_default_n; i < opts.plugin_options_n; i++)
		xfree(opts.plugin_options[i]);

	opts.plugin_options_n = opts.plugin_options_default_n;
	opts.plugin_options[opts.plugin_options_n] = NULL;
}

void cr_plugin_options_free(void)
{
	int i;

	if (!opts.plugin_options)
		return;

	for (i = 1; i < opts.plugin_options_n; i++)
		xfree(opts.plugin_options[i]);

	xfree(opts.plugin_options);
	opts.plugin_options = NULL;
	opts.plugin_options_n = 0;
	opts.plugin_options_max = 0;
	opts.plugin_options_default_n = 0;
}

int cr_plugin_option_add_arg(const char *arg)
{
	char *option;
	const char *dot, *equal;
	size_t len;

	if (!arg) {
		pr_err("Plugin option is missing\n");
		return -1;
	}

	dot = strchr(arg, '.');
	equal = strchr(arg, '=');
	len = strlen(arg);
	if (arg[0] == '-' || !dot || dot == arg || dot[1] == '\0' || (equal && equal <= dot + 1)) {
		pr_err("Invalid plugin option '%s' (expected PLUGIN.NAME[=VALUE])\n", arg);
		return -1;
	}

	if (len > SIZE_MAX - 3)
		return -1;

	if (opts.plugin_options_max < opts.plugin_options_n + 2) {
		char **new_opts;
		int new_max;

		new_max = opts.plugin_options_max * 2;
		new_opts = xrealloc(opts.plugin_options, new_max * sizeof(opts.plugin_options[0]));
		if (!new_opts)
			return -1;

		opts.plugin_options = new_opts;
		opts.plugin_options_max = new_max;
	}

	option = xzalloc(len + 3);
	if (!option)
		return -1;

	snprintf(option, len + 3, "--%s", arg);
	opts.plugin_options[opts.plugin_options_n] = option;
	opts.plugin_options_n++;
	opts.plugin_options[opts.plugin_options_n] = NULL;

	return 0;
}

int criu_plugin_get_options(int *argc, char ***argv)
{
	if (!argc || !argv)
		return -EINVAL;

	*argc = opts.plugin_options_n;
	*argv = opts.plugin_options;
	return 0;
}
