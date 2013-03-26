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
	int fd, tmpfs_fd;
	unsigned fs_cnt, fs_cnt_last = 0;

	if (mount("none", "/", "none", MS_REC|MS_PRIVATE, NULL)) {
		err("Can't remount root with MS_PRIVATE");
		return -1;
	}
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

		if (umount(mp))
			test_msg("umount(`%s') failed: %m\n", mp);
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
	rmdir(MPTS_ROOT);
	if (mkdir(MPTS_ROOT, 0600) < 0) {
		fail("Can't make zdtm_sys");
		return 1;
	}

	if (mount("none", MPTS_ROOT, "sysfs", 0, "") < 0) {
		fail("Can't mount sysfs");
		return 1;
	}

	if (mount("none", MPTS_ROOT"/dev", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	tmpfs_fd = open(MPTS_ROOT"/dev/test", O_WRONLY | O_CREAT);
	if (write(tmpfs_fd, "hello", 5) <= 0) {
		err("write() failed");
		return 1;
	}

	if (mount("none", MPTS_ROOT"/kernel", "proc", 0, "") < 0) {
		fail("Can't mount proc");
		return 1;
	}
	if (mount("none", MPTS_ROOT"/kernel/sys/fs/binfmt_misc",
					"binfmt_misc", 0, "") < 0) {
		fail("Can't mount binfmt_misc");
		return 1;
	}

	unlink("/dev/null");
	mknod("/dev/null", 0777 | S_IFCHR, makedev(1, 3));

	setup_outfile();

	fd = open(MPTS_ROOT"/kernel/meminfo", O_RDONLY);
	if (fd == -1)
		return 1;

	test_daemon();
	test_waitsig();

	/* this checks both -- sys and proc presence */
	if (access(MPTS_ROOT"/kernel/meminfo", F_OK)) {
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
