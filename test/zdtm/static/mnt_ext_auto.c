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
char *dirname_private_shared_bind = "mnt_ext_manual_private_shared_bind.test";
char *dirname_bind = "mnt_ext_manual_bind.test";
char *dirname_slave_shared_bind = "mnt_ext_manual_slave_shared_bind.test";
char *dirname_slave_bind = "mnt_ext_manual_slave_bind.test";
#define DDIR	"mtest"
#else
char *dirname = "mnt_ext_auto.test";
char *dirname_private_shared_bind = "mnt_ext_auto_private_shared_bind.test";
char *dirname_bind = "mnt_ext_auto_bind.test";
char *dirname_slave_shared_bind = "mnt_ext_auto_slave_shared_bind.test";
char *dirname_slave_bind = "mnt_ext_auto_slave_bind.test";
#define DDIR	"atest"
#endif
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char ** argv)
{
	char src[PATH_MAX], dst[PATH_MAX], *root;
	char dst_bind[PATH_MAX], dst_private_shared_bind[PATH_MAX],
		dst_slave_shared_bind[PATH_MAX], dst_slave_bind[PATH_MAX];
	char *dname = "/tmp/zdtm_ext_auto.XXXXXX";
	struct stat sta, stb, bsta, bstb, ssbsta, sbsta, ssbstb, sbstb, psbsta, psbstb;
	char* zdtm_newns = getenv("ZDTM_NEWNS");

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	sprintf(dst, "%s/%s", get_current_dir_name(), dirname);
	sprintf(dst_private_shared_bind, "%s/%s", get_current_dir_name(), dirname_private_shared_bind);
	sprintf(dst_bind, "%s/%s", get_current_dir_name(), dirname_bind);
	sprintf(dst_slave_shared_bind, "%s/%s", get_current_dir_name(), dirname_slave_shared_bind);
	sprintf(dst_slave_bind, "%s/%s", get_current_dir_name(), dirname_slave_bind);

	if (!zdtm_newns) {
		pr_perror("ZDTM_NEWNS is not set");
		return 1;
	} else if (strcmp(zdtm_newns, "1")) {
		goto test;
	}

	mkdir(dname, 755);
	sprintf(src, "%s/%s", dname, DDIR);
	if (mount("zdtm_auto_ext_mnt", dname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}
	mkdir(src, 755);

	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}
	mkdir(dst, 755);
	if (mount(src, dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	mkdir(dst_private_shared_bind, 755);
	if (mount(dst, dst_private_shared_bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount("none", dst_private_shared_bind, NULL, MS_PRIVATE, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount("none", dst_private_shared_bind, NULL, MS_SHARED, NULL)) {
		pr_perror("bind");
		return 1;
	}
	mkdir(dst_bind, 755);
	if (mount(dst_private_shared_bind, dst_bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	mkdir(dst_slave_shared_bind, 755);
	if (mount(dst_bind, dst_slave_shared_bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount("none", dst_slave_shared_bind, NULL, MS_SLAVE, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount("none", dst_slave_shared_bind, NULL, MS_SHARED, NULL)) {
		pr_perror("bind");
		return 1;
	}
	mkdir(dst_slave_bind, 755);
	if (mount(dst_slave_shared_bind, dst_slave_bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount("none", dst_slave_bind, NULL, MS_SLAVE, NULL)) {
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
	if (stat(dirname_private_shared_bind, &psbstb)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_bind, &bstb)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_slave_shared_bind, &ssbstb)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_slave_bind, &sbstb)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (stat(dirname, &sta)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_private_shared_bind, &psbsta)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_bind, &bsta)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_slave_shared_bind, &ssbsta)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}
	if (stat(dirname_slave_bind, &sbsta)) {
		pr_perror("stat");
		sleep(100);
		return 1;
	}

	if (sta.st_dev != stb.st_dev) {
		fail();
		return 1;
	}
	if (psbsta.st_dev != psbstb.st_dev) {
		fail();
		return 1;
	}
	if (bsta.st_dev != bstb.st_dev) {
		fail();
		return 1;
	}
	if (ssbsta.st_dev != ssbstb.st_dev) {
		fail();
		return 1;
	}
	if (sbsta.st_dev != sbstb.st_dev) {
		fail();
		return 1;
	}

	pass();

	return 0;
}
