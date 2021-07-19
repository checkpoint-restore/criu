#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <signal.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check two pts on ptmx";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

static const char teststr[] = "ping\n";

int main(int argc, char *argv[])
{
	char buf[sizeof(teststr)];
	int master, slave1, slave2, ret;
	char *slavename;
	struct stat st;

	uid_t new_uid = 13333;
	gid_t new_gid = 44444;

	test_init(argc, argv);

	master = open("/dev/ptmx", O_RDWR);
	if (master == -1) {
		pr_perror("open(%s) failed", "/dev/ptmx");
		return 1;
	}

	grantpt(master);
	unlockpt(master);

	slavename = ptsname(master);
	slave1 = open(slavename, O_RDWR);
	if (slave1 == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

	slave2 = open(slavename, O_RDWR);
	if (slave2 == -1) {
		pr_perror("open(%s) failed", slavename);
		return 1;
	}

#ifdef ZDTM_DEV_CONSOLE
	{
		int fd;
		fd = open("/dev/console", O_CREAT | O_RDONLY, 0755);
		if (fd < 0)
			return -1;
		close(fd);

		if (mount(slavename, "/dev/console", NULL, MS_BIND, NULL))
			return -1;
	}
#endif

	if (fchown(slave1, new_uid, new_gid)) {
		pr_perror("Can't set uid/gid on %s", slavename);
		return 1;
	}

	test_daemon();
	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	if (fstat(slave1, &st)) {
		pr_perror("Can't fetch stat on %s", slavename);
		return 1;
	}

	if (st.st_uid != new_uid || st.st_gid != new_gid) {
		fail("UID/GID mismatch (got %d/%d but %d/%d expected)", (int)st.st_uid, (int)st.st_gid, (int)new_uid,
		     (int)new_gid);
		return 1;
	}

	ret = write(master, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("write(master) failed");
		return 1;
	}

	ret = read(slave1, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("read(slave1) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	ret = write(master, teststr, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("write(master) failed");
		return 1;
	}

	ret = read(slave2, buf, sizeof(teststr) - 1);
	if (ret != sizeof(teststr) - 1) {
		pr_perror("read(slave1) failed");
		return 1;
	}

	if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
		fail("data mismatch");
		return 1;
	}

	close(master);
	close(slave1);
	close(slave2);

	pass();

	return 0;
}
