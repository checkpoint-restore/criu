#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include "zdtmtst.h"


#define FSIZE 0x3B600000ULL
#define NFILES 10
#define BUFSIZE (1<<20)

const char *test_doc = "C/R of ten big (951MiB) unlinked files in root dir";
const char *test_author = "Vitaly Ostrosablin <vostrosablin@virtuozzo.com>";

void create_check_pattern(char *buf, size_t count, unsigned char seed)
{
	int i;

	for (i = 0; i < count; i++)
		buf[i] = seed++;
}

struct fiemap *read_fiemap(int fd)
{
	test_msg("Obtaining fiemap for fd %d\n", fd);
	struct fiemap *fiemap;
	int extents_size;

	fiemap = malloc(sizeof(struct fiemap));
	if (fiemap == NULL) {
		pr_perror("Cannot allocate fiemap");
		return NULL;
	}
	memset(fiemap, 0, sizeof(struct fiemap));

	fiemap->fm_length = FIEMAP_MAX_OFFSET;
	fiemap->fm_start = 0;
	fiemap->fm_flags = 0;
	fiemap->fm_extent_count = 0;

	if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
		pr_perror("FIEMAP ioctl failed");
		return NULL;
	}

	extents_size = sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents;

	fiemap = realloc(fiemap,sizeof(struct fiemap) + extents_size);
	if (fiemap == NULL) {
		pr_perror("Cannot resize fiemap");
		return NULL;
	}
	memset(fiemap->fm_extents, 0, extents_size);

	fiemap->fm_extent_count = fiemap->fm_mapped_extents;
	fiemap->fm_mapped_extents = 0;

	if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
		pr_perror("fiemap ioctl() failed");
		return NULL;
	}
	test_msg("Debugkillme: %x\n", fiemap->fm_mapped_extents);

	return fiemap;
}

void check_extent_map(struct fiemap *map)
{
	int i;
	unsigned long long datasize = 0;
	unsigned long long holesize = 0;

	test_msg("Verifying extent map...\n");

	for (i = 0; i < map->fm_mapped_extents; i++) {
		test_msg("Extent %d, start %llx, length %llx\n",
			i,
			(long long) map->fm_extents[i].fe_logical,
			(long long) map->fm_extents[i].fe_length);

		if (i == 0)
			holesize = map->fm_extents[i].fe_logical;
		datasize += map->fm_extents[i].fe_length;
	}
	if (holesize != FSIZE) {
		pr_err("Unexpected hole size %llx != %llx\n",
			  (long long) holesize, (unsigned long long) FSIZE);
		exit(1);
	}
	if (datasize != BUFSIZE) {
		pr_err("Unexpected data size %llx != %llx\n",
			  (long long) datasize, (unsigned long long) BUFSIZE);
		exit(1);
	}
}

void compare_file_content(int fildes, int seed)
{
	char ebuf[BUFSIZE];
	char rbuf[BUFSIZE];
	char linkpath[PATH_MAX];
	int fd;
	struct fiemap *fiemap;

	ssprintf(linkpath, "/proc/self/fd/%d", fildes);

	fd = open(linkpath, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		pr_perror("Cannot open unlinked file %s", linkpath);
		exit(1);
	}

	memset(ebuf, 0, BUFSIZE);

	fiemap = read_fiemap(fd);
	check_extent_map(fiemap);
	free(fiemap);

	lseek64(fd, FSIZE, SEEK_SET);

	create_check_pattern(ebuf, BUFSIZE, seed);

	if (read(fd, rbuf, BUFSIZE) != BUFSIZE) {
		pr_perror("Cannot read %i bytes from file", BUFSIZE);
		goto failed;
	}

	if (memcmp(&ebuf, &rbuf, BUFSIZE)) {
		pr_err("Control Block: Data mismatch detected\n");
		goto failed;
	}

	close(fd);
	return;
failed:
	close(fd);
	exit(1);
}

void read_proc_fd_link(int fd, char *buf)
{
	ssize_t res;
	char linkpath[PATH_MAX];

	ssprintf(linkpath, "/proc/%d/fd/%d", getpid(), fd);

	res = readlink(linkpath, buf, PATH_MAX - 1);
	buf[res] = 0;
	if (res < 0) {
		pr_perror("Cannot read fd symlink %s", linkpath);
		exit(1);
	}
}

int create_unlinked_file(int fileno)
{
	int fd;
	char buf[BUFSIZE];
	char fnm[PATH_MAX];

	ssprintf(fnm, "/unlinked%d", fileno);
	fd = open(fnm, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0) {
		pr_perror("Cannot create file %s", fnm);
		exit(1);
	}
	test_msg("Created file: %s, fd %d\n", fnm, fd);

	if (lseek64(fd, FSIZE, SEEK_SET) < 0) {
		pr_perror("Cannot seek to offset %llx", FSIZE);
		goto failed;
	}
	test_msg("File positioning done, offset=%llx\n", FSIZE);

	create_check_pattern(&buf[0], BUFSIZE, fileno);
	if (write(fd, buf, BUFSIZE) != BUFSIZE) {
		pr_perror("Cannot write %i bytes to file", BUFSIZE);
		goto failed;
	}
	test_msg("%i bytes written to file\n", BUFSIZE);

	if (unlink(fnm) < 0) {
		pr_perror("Cannot unlink file %s", fnm);
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
	int fd[NFILES] = {0};
	char links[NFILES][PATH_MAX];
	char link[PATH_MAX];
	int count = 0;
	int tempfd;

	test_init(argc, argv);

	/* We need to create 10 unlinked files, each is around 1GB in size */
	for (count = 0; count < NFILES; count++) {

		test_msg("Creating unlinked file %d/%d\n", count + 1, NFILES);
		tempfd = create_unlinked_file(count);

		if (tempfd < 0) {
			pr_err("Cannot create unlinked file %d/%d\n",
				  count + 1, NFILES);
			return 1;
		}

		memset(&links[count][0], 0, PATH_MAX);
		read_proc_fd_link(tempfd, &links[count][0]);

		fd[count] = tempfd;
	}
	test_msg("Created %d unlinked files\n", NFILES);

	test_daemon();
	test_msg("Test daemonized, PID %d\n", getpid());
	test_waitsig();

	test_msg("PID %d resumed, doing final checks...\n", getpid());

	for (count = 0; count < NFILES; count++) {
		test_msg("Processing fd #%d (%d)\n", count, fd[count]);

		test_msg("Checking symlink consistency...\n");
		memset(&link[0], 0, PATH_MAX);
		read_proc_fd_link(fd[count], &link[0]);

		if (strcmp(&links[count][0], &link[0])) {
			pr_err("Symlink target %s has changed to %s\n",
				  links[count], link);
			return 1;
		}

		test_msg("Checking file contents...\n");
		compare_file_content(fd[count], count);

		test_msg("Closing file descriptor...\n");
		if (close(fd[count]) == -1) {
			pr_perror("Close failed");
			return 1;
		}
	}

	pass();
	return 0;
}
