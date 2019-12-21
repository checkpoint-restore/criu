#include <unistd.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

/*
 * This test reuses inotify_irmap test for testing configuration files
 * functionality. For parts not related to configuration files, please
 * refer to the original test case and it's author.
 */

const char *test_doc	= "Default configuration files usage";
const char *test_author	= "Veronika Kabatova <vkabatov@redhat.com>";

#define TDIR		"/etc"
char test_files[2][128] = {TDIR"/zdtm-test", TDIR"/zdtm-test1",};
#define CONFIG_PATH	"../../zdtm_test_config.conf"

#define BUFF_SIZE ((sizeof(struct inotify_event) + PATH_MAX))

int main (int argc, char *argv[])
{
	FILE *configfile;
	char buf[BUFF_SIZE];
	int fd, wd, i;

	test_init(argc, argv);

	for (i = 0; i < 2; i++) {
		unlink(test_files[i]);
		if (creat(test_files[i], 0600) < 0) {
			pr_perror("Can't make test file");
			exit(1);
		}
	}
	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init failed");
		goto err;
	}
	for (i = 0; i < 2; i++) {
		wd = inotify_add_watch(fd, test_files[i], IN_OPEN);
		if (wd < 0) {
			pr_perror("inotify_add_watch failed");
			goto err;
		}
	}

	configfile = fopen(CONFIG_PATH, "w");
	if (configfile == NULL) {
		pr_perror("Unable to create configuration file %s", CONFIG_PATH);
		goto err;
	}
	fprintf(configfile, "force-irmap\t\nirmap-scan-path /zdtm/static\n");
	fclose(configfile);

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		memset(buf, 0, sizeof(buf));
		wd = open(test_files[i], O_RDONLY);
		if (read(fd, buf, sizeof(buf)) <= 0) {
			fail("No events in queue");
			unlink(CONFIG_PATH);
			goto err;
		}
	}

	close(wd);
	close(fd);
	for (i = 0; i < 2; i++)
		unlink(test_files[i]);
	unlink(CONFIG_PATH);
	pass();
	return 0;
err:
	for (i = 0; i < 2; i++)
		unlink(test_files[i]);
	return 1;
}
