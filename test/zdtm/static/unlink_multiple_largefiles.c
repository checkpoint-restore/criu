#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>

#include "zdtmtst.h"

#define FSIZE 0x3B600000ULL
#define NFILES 10

const char *test_doc = "C/R of ten big (951MiB) unlinked files in root dir";
const char *test_author = "Vitaly Ostrosablin <vostrosablin@virtuozzo.com>";

int create_unlinked_file(int fileno)
{
	int fd;
	char buf[1000000];
	char fnm[15];

	sprintf(fnm, "/unlinked%d", fileno);
	fd = open(fnm, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0) {
		pr_perror("Cannot create file %s\n", fnm);
		exit(1);
	}
	test_msg("Created file: %s, fd %d\n", fnm, fd);

	if (lseek64(fd, FSIZE, SEEK_SET) < 0) {
		pr_perror("Cannot seek to offset %llx\n", FSIZE);
		goto failed;
	}
	test_msg("File positioning done, offset=%llx\n", FSIZE);

	int bufsz = sizeof(buf);
	memset(buf, 0, bufsz);
	if (write(fd, buf, bufsz) != bufsz) {
		pr_perror("Cannot write %i bytes to file\n", bufsz);
		goto failed;
	}
	test_msg("%i bytes written to file\n", bufsz);

	if (unlink(fnm) < 0) {
		pr_perror("Cannot unlink file %s\n", fnm);
		goto failed;
	}
	test_msg("File %s is unlinked\n", fnm);

	return fd;
failed:
	unlink(fnm);
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	int fd[10] = {0};
	int count = 0;

	test_init(argc, argv);

	// We need to create 10 unlinked files, each is around 1GB in size
	for (count = 0; count < NFILES; count++) {

		test_msg("Creating unlinked file %d/%d\n", count + 1, NFILES);
		int tempfd = create_unlinked_file(count);

		if (tempfd < 0) {
			pr_perror("Cannot create unlinked file %d/%d\n",
				  count + 1, NFILES);
			return 1;
		}

		fd[count] = tempfd;
	}
	test_msg("Created %d unlinked files\n", NFILES);

	test_daemon();
	test_msg("Test daemonized, PID %d\n", getpid());
	test_waitsig();

	test_msg("PID %d resumed, cleaning up...\n", getpid());

	for (count = 0; count < NFILES; count++) {
		test_msg("Closing fd #%d (%d)\n", count, fd[count]);
		if (close(fd[count]) == -1) {
			pr_perror("Close failed, errno %d\n", errno);
			return 1;
		}
	}

	pass();
	return 0;
}
