#include <sys/mount.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check ghost file on readonly fs mount restores fine";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

#define GHOST_DATA "Ghost Data"

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char ro_mount[PATH_MAX], ro_bind_mount[PATH_MAX];
	char ghost_file[PATH_MAX], ghost_file_bind[PATH_MAX];
	char buf[sizeof(GHOST_DATA)];
	int fd, fd_bind;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("zdtm_fs", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(ro_mount, "%s/ro_mount", dirname);
	if (mkdir(ro_mount, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount("ro_mount", ro_mount, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		return 1;
	}

	/*
	 * Need shared mount to check the hunk in do_bind_mount, we
	 * would have ro_bind_mount binded from ro_mount or vice versa.
	 */
	if (mount(NULL, ro_mount, NULL, MS_SHARED, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(ro_bind_mount, "%s/ro_bind_mount", dirname);
	if (mkdir(ro_bind_mount, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(ro_mount, ro_bind_mount, NULL, MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	ssprintf(ghost_file, "%s/ghost_file", ro_mount);
	fd = open(ghost_file, O_CREAT | O_WRONLY, 0600);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	if (write(fd, GHOST_DATA, sizeof(GHOST_DATA)) != sizeof(GHOST_DATA)) {
		pr_perror("write");
		return 1;
	}

	ssprintf(ghost_file_bind, "%s/ghost_file_bind", ro_bind_mount);
	fd_bind = open(ghost_file_bind, O_CREAT | O_WRONLY, 0600);
	if (fd_bind < 0) {
		pr_perror("open");
		return 1;
	}

	if (write(fd_bind, GHOST_DATA, sizeof(GHOST_DATA)) != sizeof(GHOST_DATA)) {
		pr_perror("write");
		return 1;
	}

	close(fd);
	close(fd_bind);

	fd = open(ghost_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	fd_bind = open(ghost_file_bind, O_RDONLY);
	if (fd_bind < 0) {
		pr_perror("open");
		return 1;
	}

	if (unlink(ghost_file)) {
		pr_perror("unlink");
		return 1;
	}

	if (unlink(ghost_file_bind)) {
		pr_perror("unlink");
		return 1;
	}

	if (mount(NULL, ro_mount, NULL, MS_RDONLY | MS_REMOUNT | MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	/*
	 * Need MS_NOSUID flag to check the hunk in do_bind_mount, case of
	 * different flags for mount and it's ->bind
	 */
	if (mount(NULL, ro_bind_mount, NULL, MS_NOSUID | MS_RDONLY | MS_REMOUNT | MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (read(fd, buf, sizeof(GHOST_DATA)) != sizeof(GHOST_DATA)) {
		fail("Can't read from ghost file");
		return 1;
	}

	if (strcmp(buf, GHOST_DATA)) {
		fail("Wrong data in a ghost file");
		return 1;
	}

	if (read(fd_bind, buf, sizeof(GHOST_DATA)) != sizeof(GHOST_DATA)) {
		fail("Can't read from ghost file on bind");
		return 1;
	}

	if (strcmp(buf, GHOST_DATA)) {
		fail("Wrong data in a ghost file on bind");
		return 1;
	}

	close(fd);
	close(fd_bind);

	if (umount(ro_bind_mount)) {
		pr_perror("umount");
		return 1;
	}

	if (umount(ro_mount)) {
		pr_perror("umount");
		return 1;
	}

	if (umount(dirname)) {
		pr_perror("umount");
		return 1;
	}

	pass();

	return 0;
}
