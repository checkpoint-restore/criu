#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cr_options.h"
#include "image-desc.h"
#include "image.h"
#include "magic.h"
#include "page-xfer.h"
#include "protobuf.h"
#include "remote-parent.h"
#include "servicefd.h"
#include "images/pagemap.pb-c.h"

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

static struct cr_img *create_image(int dirfd, const char *name)
{
	int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	struct cr_img *image;

	assert(fd >= 0);
	image = img_from_fd(fd);
	assert(image);
	return image;
}

static void write_test_pagemap(int dirfd, const char *name, int fd_type, u32 common_magic,
			       u32 image_magic, u32 pages_id, PagemapEntry *entries, size_t nr_entries)
{
	PagemapHead head = PAGEMAP_HEAD__INIT;
	struct cr_img *image = create_image(dirfd, name);
	size_t i;

	assert(!write_img(image, &common_magic));
	assert(!write_img(image, &image_magic));
	head.pages_id = pages_id;
	assert(pb_write_one(image, &head, PB_PAGEMAP_HEAD) >= 0);
	for (i = 0; i < nr_entries; i++)
		assert(pb_write_one(image, &entries[i], PB_PAGEMAP) >= 0);
	close_image(image);
}

static void assert_standard_pagemap(int dirfd, const char *name, int fd_type, const u32 *flags,
				    const uint64_t *vaddrs, size_t nr_entries)
{
	PagemapHead *head = NULL;
	PagemapEntry *entry = NULL;
	struct cr_img *image;
	u32 magic;
	size_t i;
	int fd;

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC);
	assert(fd >= 0);
	image = img_from_fd(fd);
	assert(image);
	assert(read_img(image, &magic) > 0 && magic == IMG_COMMON_MAGIC);
	assert(read_img(image, &magic) > 0 && magic == imgset_template[fd_type].magic);
	assert(pb_read_one(image, &head, PB_PAGEMAP_HEAD) >= 0);
	assert(head->pages_id == 0);
	pagemap_head__free_unpacked(head, NULL);

	for (i = 0; i < nr_entries; i++) {
		assert(pb_read_one_eof(image, &entry, PB_PAGEMAP) > 0);
		assert(entry->vaddr == vaddrs[i]);
		assert(entry->has_nr_pages && entry->nr_pages == 1);
		assert(entry->has_flags && entry->flags == flags[i]);
		pagemap_entry__free_unpacked(entry, NULL);
		entry = NULL;
	}
	assert(pb_read_one_eof(image, &entry, PB_PAGEMAP) == 0);
	close_image(image);
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
	char name[128] = {}, sentinel[4];
	char *image_id, *suffix;
	DIR *directory;
	int fd, ret;

	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 30, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	remote_parent_writer_close(first);
	directory = fdopendir(openat(dirfd, ".", O_RDONLY | O_DIRECTORY));
	assert(directory);
	while ((entry = readdir(directory))) {
		if (!strstr(entry->d_name, "pagemap-30.img.tmp."))
			continue;
		assert(strlen(entry->d_name) < sizeof(name));
		strcpy(name, entry->d_name);
		suffix = strrchr(name, '.');
		assert(suffix);
		sequence = strtoul(suffix + 1, NULL, 10);
	}
	assert(!closedir(directory));
	assert(sequence);

	image_id = strstr(name, "pagemap-30.img.tmp.");
	assert(image_id);
	image_id += strlen("pagemap-");
	image_id[1] = '1';
	suffix = strrchr(name, '.');
	assert(suffix);
	ret = snprintf(suffix + 1, sizeof(name) - (size_t)(suffix + 1 - name), "%lu", sequence + 1);
	assert(ret > 0 && (size_t)ret < sizeof(name) - (size_t)(suffix + 1 - name));
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

static void test_malformed_images(int dirfd)
{
	struct remote_parent_coverage *coverage = NULL;
	PagemapEntry entries[2] = { PAGEMAP_ENTRY__INIT, PAGEMAP_ENTRY__INIT };
	const char *name = "pagemap-10.img";

	entries[0].vaddr = PAGE_SIZE;
	entries[0].has_nr_pages = true;
	entries[0].nr_pages = 1;
	entries[0].has_flags = true;
	entries[0].flags = PE_PRESENT;

	write_test_pagemap(dirfd, name, CR_FD_PAGEMAP, 0, imgset_template[CR_FD_PAGEMAP].magic,
			   0, entries, 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, name, 0));

	write_test_pagemap(dirfd, name, CR_FD_PAGEMAP, IMG_COMMON_MAGIC, 0, 0, entries, 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, name, 0));

	write_test_pagemap(dirfd, name, CR_FD_PAGEMAP, IMG_COMMON_MAGIC,
			   imgset_template[CR_FD_PAGEMAP].magic, 1, entries, 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) == 0);
	assert(!coverage);
	assert(!unlinkat(dirfd, name, 0));

	entries[0].nr_pages = 0;
	write_test_pagemap(dirfd, name, CR_FD_PAGEMAP, IMG_COMMON_MAGIC,
			   imgset_template[CR_FD_PAGEMAP].magic, 0, entries, 1);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, name, 0));

	entries[0].nr_pages = 1;
	entries[0].vaddr = 2 * PAGE_SIZE;
	entries[1] = entries[0];
	entries[1].vaddr = PAGE_SIZE;
	write_test_pagemap(dirfd, name, CR_FD_PAGEMAP, IMG_COMMON_MAGIC,
			   imgset_template[CR_FD_PAGEMAP].magic, 0, entries, 2);
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, name, 0));

	assert(!symlinkat("missing", dirfd, name));
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) < 0);
	assert(!unlinkat(dirfd, name, 0));
	check_empty(dirfd);
}

/* Reusing a source directory must not turn stale local images into coverage. */
static void test_existing_source_images(int dirfd)
{
	struct remote_parent_writer *writer = NULL, *pending;
	struct iovec iov = { .iov_base = (void *)PAGE_SIZE, .iov_len = PAGE_SIZE };
	PagemapEntry entry = PAGEMAP_ENTRY__INIT;
	char original[128], actual[128], payload[4];
	int saved_mode = opts.mode;
	ssize_t length;
	int fd;

	entry.vaddr = PAGE_SIZE;
	entry.has_nr_pages = true;
	entry.nr_pages = 1;
	entry.has_flags = true;
	entry.flags = PE_PRESENT;
	write_test_pagemap(dirfd, "pagemap-10.img", CR_FD_PAGEMAP, IMG_COMMON_MAGIC,
			   imgset_template[CR_FD_PAGEMAP].magic, 42, &entry, 1);
	fd = openat(dirfd, "pagemap-10.img", O_RDONLY);
	assert(fd >= 0);
	length = read(fd, original, sizeof(original));
	assert(length > 0 && (size_t)length < sizeof(original));
	assert(!close(fd));
	fd = openat(dirfd, "pages-42.img", O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0 && write(fd, "keep", 4) == 4);
	assert(!close(fd));

	/* This source-only preflight must not change final-dump behavior. */
	opts.mode = CR_DUMP;
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &writer));
	assert(!writer);
	opts.mode = saved_mode;

	assert(!remote_parent_writer_open(CR_FD_SHMEM_PAGEMAP, 20, &pending));
	assert(!remote_parent_writer_record(pending, &iov, PE_PRESENT));
	assert(remote_parent_writer_open(CR_FD_PAGEMAP, 10, &writer) < 0);
	assert(!writer);
	assert(remote_parent_finish(true) < 0);
	assert(faccessat(dirfd, "pagemap-shmem-20.img", F_OK, 0) < 0 && errno == ENOENT);

	fd = openat(dirfd, "pagemap-10.img", O_RDONLY);
	assert(fd >= 0 && read(fd, actual, sizeof(actual)) == length);
	assert(!memcmp(actual, original, length));
	assert(!close(fd));
	fd = openat(dirfd, "pages-42.img", O_RDONLY);
	assert(fd >= 0 && read(fd, payload, sizeof(payload)) == sizeof(payload));
	assert(!memcmp(payload, "keep", sizeof(payload)));
	assert(!close(fd));
	assert(!unlinkat(dirfd, "pagemap-10.img", 0));
	assert(!unlinkat(dirfd, "pages-42.img", 0));
	check_empty(dirfd);
}

void test_remote_parent(void)
{
	char path[] = "/tmp/criu-remote-parent.XXXXXX";
	struct remote_parent_writer *first, *second;
	struct remote_parent_coverage *coverage = NULL;
	struct iovec iov = { .iov_base = (void *)PAGE_SIZE, .iov_len = PAGE_SIZE };
	const u32 expected_flags[] = { PE_PRESENT, PE_PARENT, PE_PRESENT };
	const uint64_t expected_vaddrs[] = { PAGE_SIZE, 2 * PAGE_SIZE, 4 * PAGE_SIZE };
	PagemapEntry payload_entry = PAGEMAP_ENTRY__INIT;
	int saved_mode = opts.mode;
	char sentinel[4] = {};
	int dirfd, fd, i;

	assert(mkdtemp(path));
	dirfd = open(path, O_RDONLY | O_DIRECTORY);
	assert(dirfd >= 0);
	assert(install_service_fd(IMG_FD_OFF, dirfd) >= 0);
	opts.mode = CR_PRE_DUMP;
	test_writer_open_failures(dirfd);
	test_existing_source_images(dirfd);

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
	assert_standard_pagemap(dirfd, "pagemap-10.img", CR_FD_PAGEMAP,
				expected_flags, expected_vaddrs, 3);
	/* Coverage is valid for dumping, but the ordinary payload reader rejects it. */
	{
		struct cr_img *image;
		u32 pages_id = 123;

		fd = openat(dirfd, "pagemap-10.img", O_RDONLY | O_CLOEXEC);
		assert(fd >= 0);
		assert(lseek(fd, 2 * sizeof(u32), SEEK_SET) == 2 * sizeof(u32));
		image = img_from_fd(fd);
		assert(image);
		assert(!open_pages_image_at(dirfd, O_RDONLY, image, &pages_id));
		assert(!pages_id);
		close_image(image);
	}
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) == 1);
	assert(remote_parent_coverage_contains(coverage, PAGE_SIZE, 2 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, PAGE_SIZE, 3 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, 3 * PAGE_SIZE, PAGE_SIZE));
	assert(remote_parent_coverage_contains(coverage, 4 * PAGE_SIZE, PAGE_SIZE));
	remote_parent_coverage_close(coverage);
	assert(!unlinkat(dirfd, "pagemap-10.img", 0));
	check_empty(dirfd);

	/* The same-directory page server creates its image only after OPEN2. */
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	payload_entry.vaddr = PAGE_SIZE;
	payload_entry.has_nr_pages = true;
	payload_entry.nr_pages = 1;
	payload_entry.has_flags = true;
	payload_entry.flags = PE_PRESENT;
	write_test_pagemap(dirfd, "pagemap-10.img", CR_FD_PAGEMAP, IMG_COMMON_MAGIC,
			   imgset_template[CR_FD_PAGEMAP].magic, 42, &payload_entry, 1);
	fd = openat(dirfd, "pages-42.img", O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0);
	assert(!close(fd));
	iov.iov_base = (void *)PAGE_SIZE;
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	assert(!remote_parent_finish(true));
	assert(remote_parent_coverage_open(dirfd, CR_FD_PAGEMAP, 10, &coverage) == 0);
	assert(!coverage);
	assert(!unlinkat(dirfd, "pagemap-10.img", 0));
	assert(!unlinkat(dirfd, "pages-42.img", 0));
	check_empty(dirfd);

	/* A late collision still rolls back only this transaction's publications. */
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	iov.iov_base = (void *)PAGE_SIZE;
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	assert(!remote_parent_writer_open(CR_FD_SHMEM_PAGEMAP, 20, &second));
	assert(!remote_parent_writer_record(second, &iov, PE_PRESENT));
	fd = openat(dirfd, "pagemap-10.img", O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0 && write(fd, "keep", 4) == 4);
	assert(!close(fd));
	assert(remote_parent_finish(true) < 0);
	assert(faccessat(dirfd, "pagemap-shmem-20.img", F_OK, 0) < 0 && errno == ENOENT);
	fd = openat(dirfd, "pagemap-10.img", O_RDONLY);
	assert(fd >= 0 && read(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
	assert(!memcmp(sentinel, "keep", sizeof(sentinel)));
	assert(!close(fd));
	assert(!unlinkat(dirfd, "pagemap-10.img", 0));
	check_empty(dirfd);

	/* A FIFO appearing after preflight must not block publication. */
	assert(!remote_parent_writer_open(CR_FD_PAGEMAP, 10, &first));
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	assert(!mkfifoat(dirfd, "pagemap-10.img", 0600));
	alarm(5);
	assert(remote_parent_finish(true) < 0);
	alarm(0);
	assert(!unlinkat(dirfd, "pagemap-10.img", 0));
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
	iov.iov_len = PAGE_SIZE;

	test_malformed_images(dirfd);

	/* Shared-image coverage uses offsets, including offset zero. */
	assert(!remote_parent_writer_open(CR_FD_SHMEM_PAGEMAP, 40, &first));
	iov.iov_base = NULL;
	assert(!remote_parent_writer_record(first, &iov, PE_PRESENT));
	iov.iov_base = (void *)PAGE_SIZE;
	assert(!remote_parent_writer_record(first, &iov, PE_PARENT));
	assert(!remote_parent_finish(true));
	assert(remote_parent_coverage_open(dirfd, CR_FD_SHMEM_PAGEMAP, 40, &coverage) == 1);
	assert(remote_parent_coverage_contains(coverage, 0, 2 * PAGE_SIZE));
	assert(!remote_parent_coverage_contains(coverage, 0, 3 * PAGE_SIZE));
	remote_parent_coverage_close(coverage);
	assert(!unlinkat(dirfd, "pagemap-shmem-40.img", 0));
	check_empty(dirfd);

	opts.mode = saved_mode;
	close_service_fd(IMG_FD_OFF);
	assert(!close(dirfd));
	assert(!rmdir(path));
}

