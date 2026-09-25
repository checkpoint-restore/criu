#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cr_options.h"
#include "image.h"
#include "page-xfer.h"
#include "remote-parent.h"
#include "servicefd.h"

struct coverage_header {
	uint32_t magic;
	uint32_t version;
	uint32_t type;
	uint32_t reserved;
	uint64_t id;
};

struct coverage_range {
	uint64_t start;
	uint64_t count;
};

static void write_image(int dirfd, const void *ranges, size_t size, unsigned int version)
{
	struct coverage_header header = { 0x52504352, version, CR_FD_PAGEMAP, 0, 10 };
	int fd;

	fd = openat(dirfd, "remote-parent-pagemap-10.img", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0);
	assert(write(fd, &header, sizeof(header)) == (ssize_t)sizeof(header));
	assert(write(fd, ranges, size) == (ssize_t)size);
	assert(!close(fd));
}

static void check_empty(int dirfd)
{
	struct dirent *entry;
	int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY);
	DIR *directory = fdopendir(fd);

	assert(directory);
	while ((entry = readdir(directory)))
		assert(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."));
	assert(!closedir(directory));
}

/* Exercise failures after a previous writer is already ready to commit. */
static void test_writer_open_failures(int dirfd)
{
	struct remote_parent_writer *first, *second;
	struct iovec iov = { .iov_base = (void *)PAGE_SIZE, .iov_len = PAGE_SIZE };
	struct dirent *entry;
	struct rlimit saved_limit, limit;
	struct sigaction saved_action, action = { .sa_handler = SIG_IGN };
	unsigned long sequence = 0;
	char name[128], sentinel[4];
	DIR *directory;
	int fd, ret;

	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 30, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	remote_parent_writer_close(first);
	directory = fdopendir(openat(dirfd, ".", O_RDONLY | O_DIRECTORY));
	assert(directory);
	while ((entry = readdir(directory))) {
		if (strncmp(entry->d_name, ".remote-parent-pagemap-30.img.tmp.", 32))
			continue;
		sequence = strtoul(strrchr(entry->d_name, '.') + 1, NULL, 10);
	}
	assert(!closedir(directory));
	assert(sequence);
	ret = snprintf(name, sizeof(name), ".remote-parent-pagemap-31.img.tmp.%d.%lu",
		       getpid(), sequence + 1);
	assert(ret > 0 && (size_t)ret < sizeof(name));
	fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0 && write(fd, "keep", 4) == 4);
	assert(!close(fd));
	assert(remote_parent_writer_open(CR_FD_PAGEMAP, 31, &second) < 0);
	assert(!second);
	assert(remote_parent_finish(true) < 0);
	fd = openat(dirfd, name, O_RDONLY);
	assert(fd >= 0 && read(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
	assert(!memcmp(sentinel, "keep", sizeof(sentinel)));
	assert(!close(fd));
	assert(!unlinkat(dirfd, name, 0));
	check_empty(dirfd);

	/* A real write failure, without a production fault-injection hook. */
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 30, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	remote_parent_writer_close(first);
	assert(!getrlimit(RLIMIT_FSIZE, &saved_limit));
	limit = saved_limit;
	limit.rlim_cur = 0;
	sigemptyset(&action.sa_mask);
	assert(!sigaction(SIGXFSZ, &action, &saved_action));
	assert(!setrlimit(RLIMIT_FSIZE, &limit));
	ret = remote_parent_writer_open(CR_FD_PAGEMAP, 31, &second);
	assert(!setrlimit(RLIMIT_FSIZE, &saved_limit));
	assert(!sigaction(SIGXFSZ, &saved_action, NULL));
	assert(ret < 0 && !second);
	assert(remote_parent_finish(true) < 0);
	check_empty(dirfd);

	/* A directory-FD failure must poison the complete transaction too. */
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 30, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	remote_parent_writer_close(first);
	assert(!close_service_fd(IMG_FD_OFF));
	ret = remote_parent_writer_open(CR_FD_PAGEMAP, 31, &second);
	assert(install_service_fd(IMG_FD_OFF, dirfd) >= 0);
	assert(ret < 0 && !second);
	assert(remote_parent_finish(true) < 0);
	check_empty(dirfd);
}

void test_remote_parent(void)
{
	char path[] = "/tmp/criu-remote-parent.XXXXXX";
	struct remote_parent_writer *first, *second;
	struct remote_parent_coverage *coverage = NULL;
	struct coverage_range ranges[] = { { PAGE_SIZE, 2 }, { 4 * PAGE_SIZE, 1 } };
	struct iovec iov = { .iov_base = (void *)PAGE_SIZE, .iov_len = PAGE_SIZE };
	int saved_mode = opts.mode;
	char sentinel[4] = {};
	int dirfd, fd, i;

	assert(mkdtemp(path));
	dirfd = open(path, O_RDONLY | O_DIRECTORY);
	assert(dirfd >= 0);
	assert(install_service_fd(IMG_FD_OFF, dirfd) >= 0);
	opts.mode = CR_PRE_DUMP;
	test_writer_open_failures(dirfd);

	assert(!remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage));
	assert(!coverage);
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	iov.iov_base = (void *)(2 * PAGE_SIZE);
	assert(!remote_parent_writer_record(first, &iov, PE_PARENT));
	iov.iov_base = (void *)(4 * PAGE_SIZE);
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	remote_parent_writer_close(first);
	assert(!remote_parent_coverage_exists(dirfd, CR_FD_PAGEMAP, 10));
	assert(!remote_parent_finish(true));
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) == 1);
	assert(remote_parent_coverage_contains(coverage, PAGE_SIZE, 2 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, PAGE_SIZE, 3 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, 3 * PAGE_SIZE, PAGE_SIZE));
	assert(remote_parent_coverage_contains(coverage, 4 * PAGE_SIZE, PAGE_SIZE));
	remote_parent_coverage_close(coverage);
	assert(!unlinkat(dirfd, "remote-parent-pagemap-10.img", 0));
	check_empty(dirfd);

	fd = openat(dirfd, "remote-parent-pagemap-10.img", O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0 && write(fd, "keep", 4) == 4);
	assert(!close(fd));
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	assert(!remote_parent_writer_open(CR_FD_SHMEM_PAGEMAP, 20, &second));
	assert(!remote_parent_writer_record(second, &iov, PE_PRESENT));
	assert(remote_parent_finish(true) < 0);
	assert(faccessat(dirfd, "remote-parent-shmem-20.img", F_OK, 0) < 0 && errno == ENOENT);
	fd = openat(dirfd, "remote-parent-pagemap-10.img", O_RDONLY);
	assert(fd >= 0 && read(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
	assert(!memcmp(sentinel, "keep", sizeof(sentinel)));
	assert(!close(fd));
	assert(!unlinkat(dirfd, "remote-parent-pagemap-10.img", 0));
	check_empty(dirfd);

	for (i = 0; i < 32; i++) {
		assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
		assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
		assert(!remote_parent_finish(false));
		assert(!remote_parent_finish(false));
		check_empty(dirfd);
	}

	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	iov.iov_len = 1;
	assert(remote_parent_writer_record(first, &iov, PE_PRESENT) < 0);
	assert(remote_parent_finish(true) < 0);
	check_empty(dirfd);

	write_image(dirfd, ranges, sizeof(ranges), 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) == 1);
	remote_parent_coverage_close(coverage);
	write_image(dirfd, ranges, sizeof(ranges), 2);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	write_image(dirfd, ranges, sizeof(ranges) - 1, 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	ranges[0].count = 0;
	write_image(dirfd, ranges, sizeof(ranges), 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	ranges[0].count = UINT64_MAX;
	write_image(dirfd, ranges, sizeof(ranges), 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, "remote-parent-pagemap-10.img", 0));
	assert(!symlinkat("missing", dirfd, "remote-parent-pagemap-10.img"));
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, "remote-parent-pagemap-10.img", 0));
	check_empty(dirfd);

	/* Shared-image coverage uses offsets, including offset zero. */
	assert(!remote_parent_writer_open(CR_FD_SHMEM_PAGEMAP, 40, &first));
	iov.iov_base = NULL;
	iov.iov_len = PAGE_SIZE;
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	iov.iov_base = (void *)PAGE_SIZE;
	assert(!remote_parent_writer_record(first, &iov, PE_PARENT));
	assert(!remote_parent_finish(true));
	assert(remote_parent_coverage_open(dirfd, CR_FD_SHMEM_PAGEMAP, 40, &coverage) == 1);
	assert(remote_parent_coverage_contains(coverage, 0, 2 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, 0, 3 * PAGE_SIZE));
	remote_parent_coverage_close(coverage);
	assert(!unlinkat(dirfd, "remote-parent-shmem-40.img", 0));
	check_empty(dirfd);

	opts.mode = saved_mode;
	close_service_fd(IMG_FD_OFF);
	assert(!close(dirfd));
	assert(!rmdir(path));
}
