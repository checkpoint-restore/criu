#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

#include "zdtmtst.h"

#define TEST_FILE "test_file"
#define TEST_SYMLINK "test_symlink"

const char *test_doc	= "Check open symlink preserved";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char test_symlink[PATH_MAX];
	char test_file[PATH_MAX];
	char pathbuf[PATH_MAX];
	struct stat stb, sta;
	int ret, fd;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	snprintf(test_file, sizeof(test_file), "%s/%s", dirname, TEST_FILE);
	ret = creat(test_file, 0644);
	if (ret == -1) {
		pr_perror("cat't create %s", test_file);
		return 1;
	}
	close(ret);

	snprintf(test_symlink, sizeof(test_symlink), "%s/%s", dirname, TEST_SYMLINK);
	ret = symlink(test_file, test_symlink);
	if (ret == -1) {
		pr_perror("cat't symlink to %s", test_symlink);
		return 1;
	}

	fd = open(test_symlink, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		pr_perror("cat't open symlink %s", test_symlink);
		return 1;
	}

	ret = fstat(fd, &sta);
	if (ret == -1) {
		pr_perror("cat't fstat %s", test_symlink);
		return 1;
	}

	if (!S_ISLNK(sta.st_mode)) {
		pr_perror("file is not symlink %s", test_symlink);
		return 1;
	}

#ifdef ZDTM_UNLINK_SYMLINK
	if (unlink(test_symlink)) {
		pr_perror("can't unlink symlink %s", test_symlink);
		return 1;
	}
#endif

	test_daemon();
	test_waitsig();

	ret = fstat(fd, &stb);
	if (ret == -1) {
		fail("cat't fstat %s", test_symlink);
		return 1;
	}

	if (!S_ISLNK(stb.st_mode)) {
		fail("file is not symlink %s", test_symlink);
		return 1;
	}

	ret = readlinkat(fd, "", pathbuf, sizeof(pathbuf) - 1);
	if (ret < 0) {
		fail("Can't readlinkat");
		return 1;
	}
	pathbuf[ret] = 0;

	if (strcmp(test_file, pathbuf)) {
		fail("symlink points to %s but %s expected", pathbuf, test_file);
		return 1;
	}

	close(fd);
	pass();
	return 0;
}
