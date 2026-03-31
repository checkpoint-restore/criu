#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "log.h"
#include "util.h"
#include "criu-log.h"
#include "bfd.h"

int parse_statement(int i, char *line, char **configuration);

static void test_bfd(void)
{
	struct bfd f;
	char *str;
	const int lines = 5;
	char *long_line[lines];
	int size = 1024 * 1024;
	int i, fd;

	fd = memfd_create("criu-bfd-test", 0);
	assert(fd >= 0);

	for (i = 0; i < lines; i++) {
		int j;

		long_line[i] = malloc(size + 2);
		assert(long_line[i]);
		long_line[i][0] = 'A' + (i % 26);
		for (j = 1; j < size; j++)
			long_line[i][j] = 'a' + (j % 26);
		long_line[i][size] = '\n';
		long_line[i][size + 1] = '\0';

		assert(write(fd, long_line[i], size + 1) == size + 1);
	}
	assert(lseek(fd, 0, SEEK_SET) == 0);

	f.fd = fd;
	assert(bfdopenr(&f) == 0);

	for (i = 0; i < lines; i++) {
		str = breadline(&f);
		assert(str);
		assert(strlen(str) == size);
		/* long_line has \n, str hasn't */
		assert(strcmp(str, long_line[i]) != 0);
		str[size] = '\n';
		assert(memcmp(str, long_line[i], size + 1) == 0);
	}

	bclose(&f);
	for (i = 0; i < lines; i++)
		free(long_line[i]);
}

static void test_bwrite(void)
{
	struct bfd f;
	char *buf;
	int size = 1024 * 1024;
	int i;
	int fd;
	char *read_buf;

	fd = memfd_create("criu-bfd-test", 0);
	assert(fd >= 0);

	buf = malloc(size);
	assert(buf);
	for (i = 0; i < size; i++)
		buf[i] = 'z' - (i % 26);

	f.fd = dup(fd);
	assert(f.fd >= 0);
	assert(bfdopenw(&f) == 0);

	assert(bwrite(&f, buf, size) == size);
	bclose(&f);

	assert(lseek(fd, 0, SEEK_SET) == 0);
	read_buf = malloc(size);
	assert(read_buf);
	assert(read(fd, read_buf, size) == size);
	assert(memcmp(buf, read_buf, size) == 0);

	close(fd);
	free(buf);
	free(read_buf);
}

int main(int argc, char *argv[], char *envp[])
{
	char **configuration;
	int i;

	configuration = malloc(10 * sizeof(char *));
	log_init(NULL);

	test_bfd();
	test_bwrite();

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

	pr_msg("OK\n");
	return 0;
}
