#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "zdtmtst.h"

const char *test_doc	= "Open, link, unlink former, change size, migrate, check size";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
static char link_name[1024];

int main(int argc, char ** argv)
{
	int fd;
	size_t fsize=1000;
	uint8_t buf[fsize];
	struct stat fst, fst2;
	struct statfs fsst;

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	sprintf(link_name, "%s.link", filename);
	if (link(filename, link_name)) {
		pr_perror("can't link files");
		goto failed0;
	}

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get file info %s before", filename);
		goto failed;
	}

	if (fst.st_size != 0) {
		pr_perror("%s file size eq %d", fst.st_size);
		goto failed;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

	memset(buf, '0', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (statfs(link_name, &fsst) < 0) {
		pr_perror("statfs(%s)", link_name);
		goto failed;
	}

	if (fstat(fd, &fst2) < 0) {
		pr_perror("can't get %s file info after", filename);
		goto failed;
	}

	/* An NFS mount is restored with another st_dev */
	if (fsst.f_type != NFS_SUPER_MAGIC && fst.st_dev != fst2.st_dev) {
		fail("files differ after restore\n");
		goto failed;
	}

	if (fst.st_ino != fst2.st_ino) {
		fail("files differ after restore\n");
		goto failed;
	}

	if (fst2.st_size != fsize) {
		fail("(via fstat): file size changed to %d", fst.st_size);
		goto failed;
	}

	fst2.st_size = lseek(fd, 0, SEEK_END);
	if (fst2.st_size != fsize) {
		fail("(via lseek): file size changed to %d", fst.st_size);
		goto failed;
	}

	close(fd);

	pass();
	return 0;

failed:
	unlink(link_name);
failed0:
	unlink(filename);
	close(fd);
	return 1;
}
