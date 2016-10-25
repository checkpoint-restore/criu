#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check --mnt-ext-map";
const char *test_author	= "Andrew Vagin <avagin@gmail.com>";

#ifdef ZDTM_EXTMAP_MANUAL
char *dirname = "mnt_ext_manual.test";
#define DDIR	"mtest"
#else
char *dirname = "mnt_ext_auto.test";
#define DDIR	"atest"
#endif
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char ** argv)
{
	char src[PATH_MAX], dst[PATH_MAX], *root;
	char *dname = "/tmp/zdtm_ext_auto.XXXXXX";
	struct stat sta, stb;

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	sprintf(dst, "%s/%s", get_current_dir_name(), dirname);

	if (strcmp(getenv("ZDTM_NEWNS"), "1"))
		goto test;

	mkdir(dname, 755);
	sprintf(src, "%s/%s", dname, DDIR);
	if (mount("zdtm_auto_ext_mnt", dname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}
	mkdir(src, 755);

	unshare(CLONE_NEWNS);
	mkdir(dst, 755);
	if (mount(src, dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
test:
	test_init(argc, argv);

	if (stat(dirname, &stb)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (stat(dirname, &sta)) {
		pr_perror("stat");
		return 1;
	}
	if (sta.st_dev != stb.st_dev) {
		fail();
		return 1;
	}

	pass();

	return 0;
}
