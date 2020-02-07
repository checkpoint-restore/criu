#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include "zdtmtst.h"

#define TEST_FILE "test_file"
#define BUF_SIZE 4096
#define fdinfo_field(str, field)        !strncmp(str, field":", sizeof(field))
#define pr_debug(format, arg...) test_msg("DBG: %s:%d: " format, __FILE__, __LINE__, ## arg)

const char *test_doc	= "Check open file with O_PATH preserved";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

struct fdinfo {
	int flags;
};

static int parse_self_fdinfo(int fd, struct fdinfo *fi)
{
	char path[PATH_MAX], line[BUF_SIZE];
	FILE *file;
	int ret = -1;
	unsigned long long val;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	file = fopen(path, "r");
	if (!file) {
		pr_perror("fopen");
		return -1;
	}

	while (fgets(line, sizeof(line), file)) {
		if (fdinfo_field(line, "flags")) {
			if (sscanf(line, "%*s %llo", &val) != 1) {
				pr_err("failed to read flags: %s", line);
				goto fail;
			}
			pr_debug("Open flags = %llu\n", val);
			fi->flags = val;
			ret = 0;
			break;
		}
	}
fail:
	fclose(file);
	return ret;
}

int main(int argc, char **argv)
{
	char test_file[PATH_MAX];
	struct fdinfo fi;
	int fd;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	snprintf(test_file, sizeof(test_file), "%s/%s", dirname, TEST_FILE);
	fd = creat(test_file, 0644);
	if (fd == -1) {
		pr_perror("cat't create %s", test_file);
		return 1;
	}
	close(fd);

	fd = open(test_file, O_PATH);
	if (fd == -1) {
		pr_perror("cat't open file %s with O_PATH", test_file);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (parse_self_fdinfo(fd, &fi))
		return 1;

	if (!(fi.flags & O_PATH)) {
		fail("File lost O_PATH open flag");
		return 1;
	}

	close(fd);
	pass();
	return 0;
}
