#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that tmpfs content survives checkpoint/restore";
const char *test_author = "Mallika <whoismallika@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * The content of a tmpfs mount is dumped and restored with tar, which CRIU
 * invokes with --check-links, --sparse and --preserve-permissions among
 * others. Only plain file content was covered so far, so this test exercises
 * the properties those options are supposed to preserve:
 *
 *   - hard links stay linked rather than becoming independent copies;
 *   - a sparse file keeps its size and its data, holes included;
 *   - a symlink keeps pointing at the same target;
 *   - a non-default file mode is preserved.
 */

#define SPARSE_SIZE (1 << 20)
#define SPARSE_OFF  (1 << 19)
#define DATA_SIZE   1024
#define TEST_MODE   0741
#define LINK_TARGET "target-of-the-symlink"

static uint8_t sparse_data[DATA_SIZE];
static uint32_t sparse_crc = ~0;

static int make_content(void)
{
	char path[PATH_MAX], lpath[PATH_MAX];
	int fd;

	/* A regular file plus a hard link to it. */
	ssprintf(path, "%s/hardlink.file", dirname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", path);
		return -1;
	}
	if (write(fd, "hardlinked", sizeof("hardlinked")) != sizeof("hardlinked")) {
		pr_perror("Can't write %s", path);
		close(fd);
		return -1;
	}
	close(fd);

	ssprintf(lpath, "%s/hardlink.link", dirname);
	if (link(path, lpath)) {
		pr_perror("Can't link %s to %s", path, lpath);
		return -1;
	}

	/* A sparse file: a hole followed by data. */
	ssprintf(path, "%s/sparse.file", dirname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", path);
		return -1;
	}
	datagen(sparse_data, sizeof(sparse_data), &sparse_crc);
	if (lseek(fd, SPARSE_OFF, SEEK_SET) < 0) {
		pr_perror("Can't seek in %s", path);
		close(fd);
		return -1;
	}
	if (write(fd, sparse_data, sizeof(sparse_data)) != sizeof(sparse_data)) {
		pr_perror("Can't write %s", path);
		close(fd);
		return -1;
	}
	if (ftruncate(fd, SPARSE_SIZE)) {
		pr_perror("Can't truncate %s", path);
		close(fd);
		return -1;
	}
	close(fd);

	/* A symlink. */
	ssprintf(path, "%s/symlink", dirname);
	if (symlink(LINK_TARGET, path)) {
		pr_perror("Can't create a symlink %s", path);
		return -1;
	}

	/* A file with a non-default mode. */
	ssprintf(path, "%s/mode.file", dirname);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", path);
		return -1;
	}
	close(fd);
	if (chmod(path, TEST_MODE)) {
		pr_perror("Can't chmod %s", path);
		return -1;
	}

	return 0;
}

static int check_hardlink(void)
{
	char path[PATH_MAX], lpath[PATH_MAX];
	struct stat st1, st2;

	ssprintf(path, "%s/hardlink.file", dirname);
	ssprintf(lpath, "%s/hardlink.link", dirname);

	if (stat(path, &st1)) {
		pr_perror("Can't stat %s", path);
		return -1;
	}
	if (stat(lpath, &st2)) {
		pr_perror("Can't stat %s", lpath);
		return -1;
	}

	if (st1.st_ino != st2.st_ino) {
		fail("Hard link became a separate inode");
		return -1;
	}

	if (st1.st_nlink != 2) {
		fail("Wrong link count %u, expected 2", (unsigned)st1.st_nlink);
		return -1;
	}

	return 0;
}

static int check_sparse(void)
{
	uint8_t buf[DATA_SIZE];
	uint32_t crc = ~0;
	char path[PATH_MAX];
	struct stat st;
	int fd, i;

	ssprintf(path, "%s/sparse.file", dirname);

	if (stat(path, &st)) {
		pr_perror("Can't stat %s", path);
		return -1;
	}

	if (st.st_size != SPARSE_SIZE) {
		fail("Wrong sparse file size %ld, expected %d", (long)st.st_size, SPARSE_SIZE);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	/* The hole has to read back as zeroes. */
	if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("Can't read the hole of %s", path);
		close(fd);
		return -1;
	}
	for (i = 0; i < DATA_SIZE; i++) {
		if (buf[i]) {
			fail("Hole of the sparse file is not zeroed at %d", i);
			close(fd);
			return -1;
		}
	}

	if (lseek(fd, SPARSE_OFF, SEEK_SET) < 0) {
		pr_perror("Can't seek in %s", path);
		close(fd);
		return -1;
	}
	if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("Can't read the data of %s", path);
		close(fd);
		return -1;
	}
	close(fd);

	if (datachk(buf, sizeof(buf), &crc)) {
		fail("Data of the sparse file is corrupted");
		return -1;
	}

	/*
	 * Whether the file is still stored sparsely is not part of what CRIU
	 * guarantees, so it is only reported and not checked.
	 */
	test_msg("sparse file: size %ld, %ld blocks\n", (long)st.st_size, (long)st.st_blocks);

	return 0;
}

static int check_symlink(void)
{
	char path[PATH_MAX], buf[PATH_MAX];
	ssize_t len;

	ssprintf(path, "%s/symlink", dirname);

	len = readlink(path, buf, sizeof(buf) - 1);
	if (len < 0) {
		pr_perror("Can't read the symlink %s", path);
		return -1;
	}
	buf[len] = '\0';

	if (strcmp(buf, LINK_TARGET)) {
		fail("Symlink points at '%s', expected '%s'", buf, LINK_TARGET);
		return -1;
	}

	return 0;
}

static int check_mode(void)
{
	char path[PATH_MAX];
	struct stat st;

	ssprintf(path, "%s/mode.file", dirname);

	if (stat(path, &st)) {
		pr_perror("Can't stat %s", path);
		return -1;
	}

	if ((st.st_mode & 07777) != TEST_MODE) {
		fail("Wrong mode 0%o, expected 0%o", st.st_mode & 07777, TEST_MODE);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		pr_perror("Can't mount tmpfs");
		return 1;
	}

	if (make_content())
		goto err;

	test_daemon();
	test_waitsig();

	if (check_hardlink() || check_sparse() || check_symlink() || check_mode())
		goto err;

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
