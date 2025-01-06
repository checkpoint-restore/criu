#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that binfmt_misc entries remain registered";
const char *test_author = "Kirill Tkhai <ktkhai@odin.com";

#define MAX_REG_STR	 256
#define MAX_MAGIC	 16
#define MAX_MAGIC_OFFSET 128 /* Max magic+offset */
#define MAX_EXTENSION	 128

char *dirname = "binfmt_misc.dir";
TEST_OPTION(dirname, string, "binfmt_misc mount directory name", 1);
char *filename;
TEST_OPTION(filename, string, "file name prefix (prefix_magic, prefix, extension)", 1);

char NAME[2][PATH_MAX];

/* :name:type:offset:magic:mask:interpreter:flags */

void create_magic_pattern(char *buf, const char *name)
{
	int i, magic, mask, offset;

	magic = rand() % (MAX_MAGIC + 1);
	mask = (rand() % 2) ? magic : 0;
	offset = MAX_MAGIC_OFFSET - magic;
	offset = rand() % (offset + 1);

	buf += sprintf(buf, ":%s:M:%d:", name, offset);

	for (i = 0; i < magic; i++)
		buf += sprintf(buf, "\\x%02x", rand() % 256);

	buf += sprintf(buf, ":");

	for (i = 0; i < mask; i++)
		buf += sprintf(buf, "\\x%02x", rand() % 256);

	sprintf(buf, ":/bin/interpreter:OCP");
}

void create_extension_pattern(char *buf, const char *name)
{
	int i, extension;

	extension = rand() % (MAX_EXTENSION + 1);
	buf += sprintf(buf, ":%s:E::", name);

	for (i = 0; i < extension; i++) {
		int c = rand();

		if (c == '\0' || c == ':' || c == '\n' || c == '/')
			c = '1';
		buf += sprintf(buf, "%c", c);
	}

	sprintf(buf, "::/bin/bash:");
}

int dump_content(const char *path, char **dump)
{
	int fd, len;
	char *p;

	p = *dump = malloc(PAGE_SIZE);
	if (!p) {
		fail("malloc");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fail("open");
		return -1;
	}

	len = read(fd, p, PAGE_SIZE - 1);
	close(fd);
	if (len <= 0) {
		fail("read");
		return -1;
	}

	p[len] = '\0';

	return 0;
}

int main(int argc, char **argv)
{
	char buf[MAX_REG_STR + 1];
	char path[PATH_MAX * 2 + 1];
	char *dump[2];
	int i, fd, len;

	test_init(argc, argv);

	snprintf(NAME[0], PATH_MAX, "%s_magic", filename);
	snprintf(NAME[1], PATH_MAX, "%s_extension", filename);

	if (mkdir(dirname, 0777)) {
		fail("mkdir");
		exit(1);
	}

	if (mount("none", dirname, "binfmt_misc", 0, NULL)) {
		fail("mount failed");
		exit(1);
	}

	/* Register binfmt_entries */
	sprintf(path,
		"%s/"
		"register",
		dirname);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fail("open");
		exit(1);
	}

	for (i = 0; i < 2; i++) {
		if (i % 2 == 0)
			create_magic_pattern(buf, NAME[i]);
		else
			create_extension_pattern(buf, NAME[i]);

		test_msg("string: %s\n", buf);
		len = strlen(buf);

		if (len != write(fd, buf, len)) {
			fail("write %s", NAME[i]);
			exit(1);
		}
	}

	close(fd);

	/* Disable one of the entries */
	ssprintf(path, "%s/%s", dirname, NAME[0]);
	fd = open(path, O_WRONLY);
	if (fd < 0 || write(fd, "0", 1) != 1) {
		fail("Can't disable %s", path);
		exit(1);
	}
	close(fd);

	/* Dump files content */
	for (i = 0; i < 2; i++) {
		sprintf(path, "%s/%s", dirname, NAME[i]);
		if (dump_content(path, &dump[i]))
			exit(1);
	}

	test_daemon();
	test_waitsig();

	/* Check */
	for (i = 0; i < 2; i++) {
		char *tmp;

		sprintf(path, "%s/%s", dirname, NAME[i]);
		if (dump_content(path, &tmp))
			exit(1);

		if (strcmp(tmp, dump[i])) {
			fail("Content differs:\n%s\nand\n%s", tmp, dump[i]);
			exit(1);
		}
		free(dump[i]);
		free(tmp);
	}

	pass();

	/* Clean up */
	for (i = 0; i < 2; i++) {
		sprintf(path, "%s/%s", dirname, NAME[i]);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			pr_perror("open %s", path);
			continue;
		}
		if (write(fd, "-1", 2) != 2)
			pr_perror("cleanup %s", path);
		close(fd);
	}

	umount(dirname);
	rmdir(dirname);

	return 0;
}
