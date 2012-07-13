#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that mountpoints (in mount namespace) are supported";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#define MPTS_ROOT	"/zdtm_mpts/"

static char buf[1024];

static int test_fn(int argc, char **argv)
{
	FILE *f;
	unsigned fs_cnt, fs_cnt_last = 0;

again:
	fs_cnt = 0;
	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		fail("Can't open mountinfo");
		return -1;
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *mp = buf, *end;

		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		end = strchr(mp, ' ');
		*end = '\0';

		if (!strcmp(mp, "/"))
			continue;
		if (!strcmp(mp, "/proc"))
			continue;

		umount(mp);
		fs_cnt++;
	}

	fclose(f);

	if (fs_cnt == 0)
		goto done;

	if (fs_cnt != fs_cnt_last) {
		fs_cnt_last = fs_cnt;
		goto again;
	}

	fail("Can't umount all the filesystems");
	return -1;

done:
	close(0);
	close(1);
	close(2);
	rmdir(MPTS_ROOT);
	if (mkdir(MPTS_ROOT, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (mount("none", MPTS_ROOT, "sysfs", 0, "") < 0) {
		fail("Can't mount sysfs");
		return 1;
	}

	if (mount("none", MPTS_ROOT"/kernel", "proc", 0, "") < 0) {
		fail("Can't mount proc");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* this checks both -- sys and proc presence */
	if (access(MPTS_ROOT"/kernel/slabinfo", F_OK)) {
		fail("No proc after restore");
		return 1;
	}

	pass();
	return 0;
}

#define CLONE_NEWNS     0x00020000

int main(int argc, char **argv)
{
	test_init_ns(argc, argv, CLONE_NEWNS, test_fn);
	return 0;
}
