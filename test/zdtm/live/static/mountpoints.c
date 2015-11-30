#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that mountpoints (in mount namespace) are supported";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#define MPTS_ROOT	"/zdtm_mpts/"

static char buf[1024];

#define NS_STACK_SIZE	4096
/* All arguments should be above stack, because it grows down */
struct ns_exec_args {
	char stack[NS_STACK_SIZE];
	char stack_ptr[0];
	int status_pipe[2];
};

int ns_child(void *_arg)
{
	struct stat st;
	pid_t pid;
	int fd, ufd;

	mkdir(MPTS_ROOT"/dev/mntns2", 0600);
	if (mount("none", MPTS_ROOT"/dev/mntns2", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/mntns2/test", 0600);

	fd = open(MPTS_ROOT"/dev/mntns2/test/test.file", O_WRONLY | O_CREAT, 0666);
	if (fd < 0)
		return 1;

	ufd = open(MPTS_ROOT"/dev/mntns2/test/test.file.unlinked", O_WRONLY | O_CREAT, 0666);
	if (ufd < 0)
		return 1;
	unlink(MPTS_ROOT"/dev/mntns2/test/test.file.unlinked");

	pid = fork();

	test_waitsig();

	if (pid) {
		int status = 1;;
		kill(pid, SIGTERM);
		wait(&status);
		if (status)
			return 1;
	}

	if (stat(MPTS_ROOT"/dev/mntns2/test", &st)) {
		pr_perror("Can't stat /dev/share-1/test.share/test.share");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	FILE *f;
	int fd, tmpfs_fd, have_bfmtm = 0;
	unsigned fs_cnt, fs_cnt_last = 0;
	struct ns_exec_args args;
	mode_t old_mask;
	pid_t pid = -1;

	test_init(argc, argv);

again:
	fs_cnt = 0;
	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		fail("Can't open mountinfo");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)) {
		pr_perror("Can't remount / with MS_PRIVATE");
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
		pr_perror("write() failed");
		return 1;
	}

	/* Check that over-mounted files are restored on tmpfs */
	mkdir(MPTS_ROOT"/dev/overmount", 0600);
	fd = open(MPTS_ROOT"/dev/overmount/test.over", O_WRONLY | O_CREAT);
	if (fd == -1) {
		pr_perror("Unable to open "MPTS_ROOT"/dev/overmount");
		return -1;
	}
	close(fd);
	if (mount("none", MPTS_ROOT"/dev/overmount", "tmpfs", 0, "") < 0) {
		pr_perror("Can't mount "MPTS_ROOT"/dev/overmount");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/non-root", 0600);
	if (mount(MPTS_ROOT"/dev/non-root", MPTS_ROOT"/module", NULL, MS_BIND, NULL) < 0) {
		pr_perror("Can't bind-mount %s -> %s", MPTS_ROOT"/dev/tdir", MPTS_ROOT"/module");
	}
	mkdir(MPTS_ROOT"/dev/non-root/test", 0600);

	mkdir(MPTS_ROOT"/dev/share-1", 0600);
	if (mount("none", MPTS_ROOT"/dev/share-1/", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	if (mount("none", MPTS_ROOT"/dev/share-1/", NULL, MS_SHARED, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

//#define CR_NEXT
#ifdef CR_NEXT
	mkdir(MPTS_ROOT"/dev/share-1/alone", 0600);
	if (mount("none", MPTS_ROOT"/dev/share-1/alone", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
#endif

	mkdir(MPTS_ROOT"/dev/share-2", 0600);
	if (mount(MPTS_ROOT"/dev/share-1", MPTS_ROOT"/dev/share-2", NULL, MS_BIND, NULL) < 0) {
		fail("Can't bind mount a tmpfs directory");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/share-3", 0600);
	if (mount(MPTS_ROOT"/dev/share-1", MPTS_ROOT"/dev/share-3", NULL, MS_BIND, NULL) < 0) {
		fail("Can't bind mount a tmpfs directory");
		return 1;
	}
	mkdir(MPTS_ROOT"/dev/slave", 0600);
	if (mount(MPTS_ROOT"/dev/share-1", MPTS_ROOT"/dev/slave", NULL, MS_BIND, NULL) < 0) {
		fail("Can't bind mount a tmpfs directory");
		return 1;
	}
	if (mount("none", MPTS_ROOT"/dev/slave", NULL, MS_SLAVE, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/slave2", 0600);
	if (mount(MPTS_ROOT"/dev/share-3", MPTS_ROOT"/dev/slave2", NULL, MS_BIND, NULL) < 0) {
		fail("Can't bind mount a tmpfs directory");
		return 1;
	}
	if (mount("none", MPTS_ROOT"/dev/slave2", NULL, MS_SLAVE, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/share-1/test.mnt.share", 0600);
	if (mount("none", MPTS_ROOT"/dev/share-1/test.mnt.share", "tmpfs", 0, "size=1G") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/share-1/test.mnt.share/test.share", 0600);
	if (umount(MPTS_ROOT"/dev/slave2/test.mnt.share")) {
		pr_perror("Can't umount "MPTS_ROOT"/dev/slave2/test.mnt.share");
		return 1;
	}

	mkdir(MPTS_ROOT"/dev/slave/test.mnt.slave", 0600);
	if (mount("none", MPTS_ROOT"/dev/slave/test.mnt.slave", "tmpfs", 0, "") < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}
	mkdir(MPTS_ROOT"/dev/slave/test.mnt.slave/test.slave", 0600);

	fd = open(MPTS_ROOT"/dev/bmfile", O_CREAT | O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't create " MPTS_ROOT "/dev/share-1/bmfile");
		return 1;
	}
	close(fd);

	fd = open(MPTS_ROOT"/dev/bmfile-mount", O_CREAT | O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't create " MPTS_ROOT "/dev/share-1/bmfile");
		return 1;
	}
	close(fd);

	if (mount(MPTS_ROOT"/dev/bmfile", MPTS_ROOT"/dev/bmfile-mount", NULL, MS_BIND, NULL) < 0) {
		fail("Can't mount tmpfs");
		return 1;
	}

	if (mount("none", MPTS_ROOT"/kernel", "proc", 0, "") < 0) {
		fail("Can't mount proc");
		return 1;
	}

	if (mount("none", MPTS_ROOT"/kernel/sys/fs/binfmt_misc",
					"binfmt_misc", 0, "") == 0)
		have_bfmtm = 1;

	unlink("/dev/null");
	/*
	 * Clear umask first, create readable & writeable /dev/null,
	 * and change it back. This is done to ensure that file mode
	 * creation mask will not impede it to create file that grants
	 * read and write permission to all users.
	 */
	old_mask = umask(0);
	mknod("/dev/null", 0777 | S_IFCHR, makedev(1, 3));
	umask(old_mask);

	fd = open(MPTS_ROOT"/kernel/meminfo", O_RDONLY);
	if (fd == -1)
		return 1;

	if (getenv("ZDTM_NOSUBNS") == NULL) {
		pid = clone(ns_child, args.stack_ptr, CLONE_NEWNS | SIGCHLD, &args);
		if (pid < 0) {
			pr_perror("Unable to fork child");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	/* this checks both -- sys and proc presence */
	if (access(MPTS_ROOT"/kernel/meminfo", F_OK)) {
		fail("No proc after restore");
		return 1;
	}

	if (have_bfmtm && access(MPTS_ROOT"/kernel/sys/fs/binfmt_misc/register", F_OK)) {
		fail("No binfmt_misc after restore");
		return 1;
	}

	if (umount(MPTS_ROOT"/dev/overmount") == -1) {
		pr_perror("Can't umount "MPTS_ROOT"/dev/overmount");
		return -1;
	}
	if (access(MPTS_ROOT"/dev/overmount/test.over", F_OK)) {
		fail(MPTS_ROOT"/dev/overmount/test.over");
		return -1;
	}

	{
		struct stat st1, st2;
		if (stat(MPTS_ROOT"/dev/share-1/test.mnt.share/test.share", &st1)) {
			pr_perror("Can't stat /dev/share-1/test.share/test.share");
			return 1;
		}
		if (stat(MPTS_ROOT"/dev/share-2/test.mnt.share/test.share", &st2)) {
			pr_perror("Can't stat /dev/share-2/test.mnt.share/test.share");
			return 1;
		}
		if (st1.st_ino != st2.st_ino) {
			fail("/dev/share-1 and /dev/share-1 is not shared");
			return 1;
		}
		if (stat(MPTS_ROOT"/dev/slave/test.mnt.share/test.share", &st2)) {
			pr_perror("Can't stat /dev/slave/test.mnt.share/test.share");
			return 1;
		}
		if (st1.st_ino != st2.st_ino) {
			fail("/dev/slave is not slave of /dev/share-1");
			return 1;
		}
		if (stat(MPTS_ROOT"/dev/share-1/test.mnt.slave/test.slave", &st1) != -1 || errno != ENOENT) {
			pr_perror("/dev/share-1/test.mnt.slave/test.slave exists");
			return 1;
		}
		if (stat(MPTS_ROOT"/dev/slave/test.mnt.slave/test.slave", &st2)) {
			pr_perror("Can't stat /dev/slave/test.mnt.slave/test.slave");
			return 1;
		}
		if (stat(MPTS_ROOT"/dev/non-root/test", &st1)) {
			pr_perror("Can't stat /dev/non-root/test");
			return 1;
		}
	}

	if (pid > 0) {
		kill(pid, SIGTERM);
		int status = 1;
		wait(&status);
		if (status)
			return 1;
	}

	pass();
	return 0;
}
