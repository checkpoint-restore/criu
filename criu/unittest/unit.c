#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "log.h"
#include "util.h"
#include "criu-log.h"

int parse_statement(int i, char *line, char **configuration);
int parse_action_env(char *input, char *name, char **value);

void test_action_env(char **configuration)
{
	int i;
	char name[255], *value;

	i = parse_statement(0, "action-env FOO=BAR\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--action-env"));
	assert(!strcmp(configuration[1], "FOO=BAR"));

	// Should fail if the value does not contain equal sign
	i = parse_action_env("TEST", NULL, NULL);
	assert(i == -1);

	// Should fail if the env name is empty
	i = parse_action_env("=TEST", NULL, NULL);
	assert(i == -1);

	// Should fail if the env value is empty
	i = parse_action_env("TEST=", NULL, NULL);
	assert(i == -1);

	i = parse_action_env("FOO=BAR", name, &value);
	assert(i == 0);
	assert(!strcmp(name, "FOO"));
	assert(!strcmp(value, "BAR"));
}

int main(int argc, char *argv[], char *envp[])
{
	char **configuration;
	int i;

	configuration = malloc(10 * sizeof(char *));
	log_init(NULL);

	i = parse_statement(0, "", configuration);
	assert(i == 0);

	i = parse_statement(0, "\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "# comment\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "#comment\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "tcp-close #comment\n", configuration);
	assert(i == 1);
	assert(!strcmp(configuration[0], "--tcp-close"));

	i = parse_statement(0, " tcp-close #comment\n", configuration);
	assert(i == 1);
	assert(!strcmp(configuration[0], "--tcp-close"));

	i = parse_statement(0, "test \"test\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--test"));
	assert(!strcmp(configuration[1], "test"));

	i = parse_statement(0, "dsfa \"aaaaa \\\"bbbbbb\\\"\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--dsfa"));
	assert(!strcmp(configuration[1], "aaaaa \"bbbbbb\""));

	i = parse_statement(0, "verbosity 4\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity \"\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "verbosity 4#comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4 #comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4  #comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--verbosity"));
	assert(!strcmp(configuration[1], "4"));

	i = parse_statement(0, "verbosity 4 no-comment\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "lsm-profile \"\" # more comments\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], ""));

	i = parse_statement(0, "lsm-profile \"something\"# comment\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], "something"));

	i = parse_statement(0, "#\n", configuration);
	assert(i == 0);

	i = parse_statement(0, "lsm-profile \"selinux:something\\\"with\\\"quotes\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--lsm-profile"));
	assert(!strcmp(configuration[1], "selinux:something\"with\"quotes"));

	i = parse_statement(0, "work-dir \"/tmp with spaces\" no-comment\n", configuration);
	assert(i == -1);

	i = parse_statement(0, "work-dir \"/tmp with spaces\"\n", configuration);
	assert(i == 2);
	assert(!strcmp(configuration[0], "--work-dir"));
	assert(!strcmp(configuration[1], "/tmp with spaces"));

	i = parse_statement(0, "a b c d e f g h i\n", configuration);
	assert(i == -1);

	/* get_relative_path */
	/* different kinds of representation of "/" */
	assert(!strcmp(get_relative_path("/", "/"), ""));
	assert(!strcmp(get_relative_path("/", ""), ""));
	assert(!strcmp(get_relative_path("", "/"), ""));
	assert(!strcmp(get_relative_path(".", "/"), ""));
	assert(!strcmp(get_relative_path("/", "."), ""));
	assert(!strcmp(get_relative_path("/", "./"), ""));
	assert(!strcmp(get_relative_path("./", "/"), ""));
	assert(!strcmp(get_relative_path("/.", "./"), ""));
	assert(!strcmp(get_relative_path("./", "/."), ""));
	assert(!strcmp(get_relative_path(".//////.", ""), ""));
	assert(!strcmp(get_relative_path("/./", ""), ""));

	/* all relative paths given are assumed relative to "/" */
	assert(!strcmp(get_relative_path("/a/b/c", "a/b/c"), ""));

	/* multiple slashes are ignored, only directory names matter */
	assert(!strcmp(get_relative_path("///alfa///beta///gamma///", "//alfa//beta//gamma//"), ""));

	/* returned path is always relative */
	assert(!strcmp(get_relative_path("/a/b/c", "/"), "a/b/c"));
	assert(!strcmp(get_relative_path("/a/b/c", "/a/b"), "c"));

	/* single dots supported */
	assert(!strcmp(get_relative_path("./a/b", "a/"), "b"));

	/* double dots are partially supported */
	assert(!strcmp(get_relative_path("a/../b", "a"), "../b"));
	assert(!strcmp(get_relative_path("a/../b", "a/.."), "b"));
	assert(!get_relative_path("a/../b/c", "b"));

	/* if second path is not subpath - NULL returned */
	assert(!get_relative_path("/a/b/c", "/a/b/d"));
	assert(!get_relative_path("/a/b", "/a/b/c"));
	assert(!get_relative_path("/a/b/c/d", "b/c/d"));

	assert(!strcmp(get_relative_path("./a////.///./b//././c", "///./a/b"), "c"));

	/* leaves punctuation in returned string as is */
	assert(!strcmp(get_relative_path("./a////.///./b//././c", "a"), "b//././c"));

	test_action_env(configuration);

	pr_msg("OK\n");
	return 0;
}
