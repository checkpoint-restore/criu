#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "criu-plugin.h"

#define TEST_PLUGIN_NAME  "test-plugin"
#define TEST_OPTION_NAME  "test-option"
#define TEST_OPTION_VALUE "test-value"
#define TEST_LONG_OPTION  TEST_PLUGIN_NAME "." TEST_OPTION_NAME

static int test_plugin_print_help(void)
{
	printf("\nTest plugin options:\n"
	       "  --plugin-option=test-plugin.test-option=VALUE\n"
	       "                        Set the RPC plugin test value\n");
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PRINT_HELP, test_plugin_print_help)

static bool test_plugin_option_matches(const char *arg, const char *name)
{
	size_t len = strlen(name);

	return !strncmp(arg, "--", 2) && !strncmp(arg + 2, name, len) &&
	       arg[len + 2] == '=';
}

static int record_test_plugin_option(void)
{
	const char *path = getenv("CRIU_PLUGIN_OPTION_MARKER");
	FILE *marker;
	int ret = 0;

	if (!path)
		return 0;

	marker = fopen(path, "w");
	if (!marker)
		return -errno;
	if (fputs(TEST_OPTION_VALUE "\n", marker) == EOF)
		ret = -EIO;
	if (fclose(marker) && !ret)
		ret = -errno;

	return ret;
}

static int test_plugin_init(int stage)
{
	static const struct option options[] = {
		{ TEST_LONG_OPTION, required_argument, NULL, 't' },
		{},
	};
	char **argv = NULL;
	char *saved_optarg;
	const char *value = NULL;
	int saved_optopt;
	int saved_opterr;
	int saved_optind;
	int argc;
	int option;
	int ret = 0;

	(void)stage;
	if (getenv("CRIU_PLUGIN_HELP_TEST"))
		return -EINVAL;

	ret = criu_plugin_get_options(&argc, &argv);
	if (ret)
		return ret;

	saved_optarg = optarg;
	saved_optopt = optopt;
	saved_opterr = opterr;
	saved_optind = optind;
	opterr = 0;
	optind = 0;
	while ((option = getopt_long(argc, argv, ":", options, NULL)) != -1) {
		switch (option) {
		case 't':
			if (test_plugin_option_matches(argv[optind - 1], TEST_LONG_OPTION))
				value = optarg;
			break;
		case '?':
			/* The option belongs to another plugin. */
			break;
		case ':':
		default:
			ret = -EINVAL;
			goto restore_getopt;
		}
	}
restore_getopt:
	optarg = saved_optarg;
	optopt = saved_optopt;
	opterr = saved_opterr;
	optind = saved_optind;

	if (ret)
		return ret;
	if (value && strcmp(value, TEST_OPTION_VALUE))
		return -EINVAL;
	if (value)
		return record_test_plugin_option();
	return 0;
}

static void test_plugin_exit(int stage, int ret)
{
	(void)stage;
	(void)ret;
	if (getenv("CRIU_PLUGIN_HELP_TEST"))
		abort();
}

CR_PLUGIN_REGISTER(TEST_PLUGIN_NAME, test_plugin_init, test_plugin_exit)
