#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "zdtmtst.h"

static struct long_opt *opt_head;

static int help;
TEST_OPTION(help, bool, "print help message and exit", 0);

void __push_opt(struct long_opt *opt)
{
	opt->next = opt_head;
	/* FIXME: barrier ? */
	opt_head = opt;
}

int parse_opt_bool(char *param, void *arg)
{
	if (param == NULL ||
	    !strcmp(param, "on") ||
	    !strcmp(param, "yes") ||
	    !strcmp(param, "true")) {
		* (int *) arg = 1;
		return 0;
	}
	if (!strcmp(param, "off") ||
	    !strcmp(param, "no") ||
	    !strcmp(param, "false")) {
		* (int *) arg = 0;
		return 0;
	}
	return -EINVAL;
}

int parse_opt_int(char *param, void *arg)
{
	char *tail;
	if (param == NULL || param[0] == '\0')
		return -EINVAL;
	* (int *) arg = strtol(param, &tail, 0);
	if (tail[0] != '\0')
		return -EINVAL;
	return 0;
}

int parse_opt_uint(char *param, void *arg)
{
	char *tail;
	if (param == NULL || param[0] == '\0')
		return -EINVAL;
	* (unsigned int *) arg = strtoul(param, &tail, 0);
	if (tail[0] != '\0')
		return -EINVAL;
	return 0;
}

int parse_opt_long(char *param, void *arg)
{
	char *tail;
	if (param == NULL || param[0] == '\0')
		return -EINVAL;
	* (long *) arg = strtol(param, &tail, 0);
	if (tail[0] != '\0')
		return -EINVAL;
	return 0;
}

int parse_opt_ulong(char *param, void *arg)
{
	char *tail;
	if (param == NULL || param[0] == '\0')
		return -EINVAL;
	* (unsigned long *) arg = strtoul(param, &tail, 0);
	if (tail[0] != '\0')
		return -EINVAL;
	return 0;
}

int parse_opt_string(char *param, void *arg)
{
	if (param == NULL || param[0] == '\0')
		return -EINVAL;
	* (char **) arg = param;
	return 0;
}

static void printopt(const struct long_opt *opt)
{
	const char *obracket = "", *cbracket = "";

	if (!opt->is_required) {
		obracket = "[";
		cbracket = "]";
	}

	fprintf(stderr, "  %s--%s=%s%s\t%s\n",
		obracket, opt->name, opt->type, cbracket, opt->doc);
}

static void helpexit(void)
{
	struct long_opt *opt;

	fputs("Usage:\n", stderr);

	for (opt = opt_head; opt; opt = opt->next)
		printopt(opt);

	exit(1);
}

const char *test_doc;
const char *test_author;

static void prdoc(void)
{
	if (test_doc)
		fprintf(stderr, "%s\n", test_doc);
	if (test_author)
		fprintf(stderr, "Author: %s\n", test_author);
}

void parseargs(int argc, char ** argv)
{
	int i;
	struct long_opt *opt;

	for (i = 1; i < argc; i++) {
		char *name, *value;

		if (strlen(argv[i]) < 2 || strncmp(argv[i], "--", 2)) {
			fprintf(stderr, "%s: options should start with --\n", argv[i]);
			helpexit();
		}

		name = argv[i] + 2;

		value = strchr(name, '=');
		if (value)
			value++;

		for (opt = opt_head; opt; opt = opt->next)
			if (!strncmp(name, opt->name, value - name - 1)) {
				if (opt->parse_opt(value, opt->value)) {
					fprintf(stderr, "%s: failed to parse\n", argv[i]);
					helpexit();
				}
				else
					/* -1 marks fulfilled requirement */
					opt->is_required = - opt->is_required;

				break;
			}

		if (!opt) {
			fprintf(stderr, "%s: unknown option\n", argv[i]);
			helpexit();
		}
	}

	if (help) {
		prdoc();
		helpexit();
	}

	for (opt = opt_head; opt; opt = opt->next)
		if (opt->is_required > 0) {
			fprintf(stderr, "mandatory flag --%s not given\n", opt->name);
			helpexit();
		}
}
