#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cr_options.h"
#include "image-desc.h"
#include "image.h"
#include "log.h"
#include "magic.h"
#include "page-xfer.h"
#include "protobuf.h"
#include "remote-parent.h"
#include "servicefd.h"
#include "util.h"
#include "images/pagemap.pb-c.h"

/*
 * The source-side file is a regular CRIU pagemap image. It contains no page
 * payload, so pages_id is zero and the file is used only to validate parent
 * ranges during the later local dump.
 */
struct remote_parent_range {
	unsigned long start;
	unsigned long end;
};

struct remote_parent_coverage {
	struct remote_parent_range *ranges;
	size_t nr_ranges;
	size_t capacity;
};

struct remote_parent_writer {
	struct cr_img *image;
	int dirfd;
	int fd_type;
	char tmp_name[96];
	char final_name[80];
	bool published;
	bool tmp_created;
	bool have_entry;
	uint64_t last_end;
	struct remote_parent_writer *next;
};

static struct remote_parent_writer *pending_writers;
static unsigned long writer_sequence;
static bool writer_error;

static int coverage_name(char *buf, size_t size, int fd_type, unsigned long img_id)
{
	int ret;

	if (fd_type == CR_FD_PAGEMAP)
		ret = snprintf(buf, size, "pagemap-%lu.img", img_id);
	else if (fd_type == CR_FD_SHMEM_PAGEMAP)
		ret = snprintf(buf, size, "pagemap-shmem-%lu.img", img_id);
	else
		return 0;

	if (ret < 0 || (size_t)ret >= size) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return 1;
}

static int write_pagemap_header(struct cr_img *image, int fd_type)
{
	PagemapHead head = PAGEMAP_HEAD__INIT;
	u32 magic = IMG_COMMON_MAGIC;

	if (write_img(image, &magic))
		return -1;
	magic = imgset_template[fd_type].magic;
	if (write_img(image, &magic))
		return -1;

	/* No pages image exists on the source side. */
	head.pages_id = 0;
	return pb_write_one(image, &head, PB_PAGEMAP_HEAD);
}

int remote_parent_writer_open(int fd_type, unsigned long img_id, struct remote_parent_writer **out)
{
	struct remote_parent_writer *writer;
	struct stat st;
	int base_fd;
	int fd = -1;
	int ret;

	*out = NULL;
	if (opts.mode != CR_PRE_DUMP)
		return 0;

	writer = xzalloc(sizeof(*writer));
	if (!writer) {
		writer_error = true;
		return -1;
	}
	writer->dirfd = -1;
	writer->fd_type = fd_type;

	ret = coverage_name(writer->final_name, sizeof(writer->final_name), fd_type, img_id);
	if (ret < 0)
		goto err;
	if (!ret) {
		xfree(writer);
		return 0;
	}

	ret = snprintf(writer->tmp_name, sizeof(writer->tmp_name), ".%s.tmp.%d.%lu", writer->final_name, getpid(),
		       ++writer_sequence);
	if (ret < 0 || (size_t)ret >= sizeof(writer->tmp_name)) {
		errno = ENAMETOOLONG;
		goto err;
	}

	base_fd = get_service_fd(IMG_FD_OFF);
	writer->dirfd = fcntl(base_fd, F_DUPFD_CLOEXEC, 0);
	if (writer->dirfd < 0) {
		pr_perror("Unable to duplicate image directory");
		goto err;
	}

	/* Check before OPEN2 lets a same-directory receiver create its own image. */
	ret = fstatat(writer->dirfd, writer->final_name, &st, AT_SYMLINK_NOFOLLOW);
	if (!ret || errno != ENOENT) {
		if (!ret)
			errno = EEXIST;
		pr_perror("Source pagemap must not already exist: %s", writer->final_name);
		goto err;
	}

	fd = openat(writer->dirfd, writer->tmp_name,
		    O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		pr_perror("Unable to create remote-parent pagemap %s", writer->tmp_name);
		goto err;
	}
	writer->tmp_created = true;

	writer->image = img_from_fd(fd);
	if (!writer->image)
		goto err;
	fd = -1;

	if (write_pagemap_header(writer->image, fd_type)) {
		pr_err("Unable to write remote-parent pagemap header\n");
		goto err;
	}

	writer->next = pending_writers;
	pending_writers = writer;
	*out = writer;
	return 0;

err:
	/* An earlier writer must not be published after this open failed. */
	writer_error = true;
	if (writer->image)
		close_image(writer->image);
	else if (fd >= 0)
		close(fd);
	if (writer->dirfd >= 0) {
		if (writer->tmp_created)
			unlinkat(writer->dirfd, writer->tmp_name, 0);
		close(writer->dirfd);
	}
	xfree(writer);
	return -1;
}

int remote_parent_writer_record(struct remote_parent_writer *writer, const struct iovec *iov, u32 flags)
{
	PagemapEntry entry = PAGEMAP_ENTRY__INIT;
	uint64_t vaddr;
	uint64_t nr_pages;
	uint64_t end;

	if (!writer || !(flags & (PE_PRESENT | PE_PARENT)))
		return 0;

	if (!iov->iov_len || iov->iov_len % PAGE_SIZE) {
		pr_err("Invalid remote-parent pagemap length %zu\n", iov->iov_len);
		goto err;
	}

	vaddr = (uintptr_t)iov->iov_base;
	nr_pages = iov->iov_len / PAGE_SIZE;
	if ((vaddr & (PAGE_SIZE - 1)) || nr_pages > (UINT64_MAX - vaddr) / PAGE_SIZE) {
		pr_err("Invalid remote-parent pagemap range at %#" PRIx64 "\n", vaddr);
		goto err;
	}
	end = vaddr + nr_pages * PAGE_SIZE;
	if (writer->have_entry && vaddr < writer->last_end) {
		pr_err("Overlapping or out-of-order remote-parent pagemap at %#" PRIx64 "\n", vaddr);
		goto err;
	}

	entry.vaddr = vaddr;
	entry.nr_pages = nr_pages;
	entry.has_nr_pages = true;
	entry.flags = flags;
	entry.has_flags = true;
	if (pb_write_one(writer->image, &entry, PB_PAGEMAP) < 0) {
		pr_err("Unable to write remote-parent pagemap entry\n");
		goto err;
	}

	writer->have_entry = true;
	writer->last_end = end;
	return 0;

err:
	writer_error = true;
	return -1;
}

void remote_parent_writer_close(struct remote_parent_writer *writer)
{
	if (!writer || !writer->image)
		return;

	close_image(writer->image);
	writer->image = NULL;
}

static int unlink_coverage(int dirfd, const char *name)
{
	if (!unlinkat(dirfd, name, 0) || errno == ENOENT)
		return 0;

	pr_perror("Unable to remove remote-parent pagemap %s", name);
	return -1;
}

static int existing_payload_pagemap(struct remote_parent_writer *writer)
{
	PagemapHead *head = NULL;
	struct cr_img *image = NULL;
	struct stat st;
	char pages_name[64];
	u32 magic;
	int fd = -1;
	int ret = 0;

	fd = openat(writer->dirfd, writer->final_name, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0)
		return errno == ENOENT ? 0 : -1;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		return -1;
	}

	image = img_from_fd(fd);
	if (!image) {
		close(fd);
		return -1;
	}

	if (read_img(image, &magic) <= 0 || magic != IMG_COMMON_MAGIC)
		goto out;
	if (read_img(image, &magic) <= 0 || magic != imgset_template[writer->fd_type].magic)
		goto out;
	if (pb_read_one(image, &head, PB_PAGEMAP_HEAD) < 0)
		goto out;
	if (!head->pages_id)
		goto out;

	{
		int len = snprintf(pages_name, sizeof(pages_name), "pages-%u.img", head->pages_id);

		if (len < 0 || (size_t)len >= sizeof(pages_name))
			goto out;
	}
	if (!fstatat(writer->dirfd, pages_name, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode))
		ret = 1;
out:
	if (head)
		pagemap_head__free_unpacked(head, NULL);
	close_image(image);
	return ret;
}

static int writer_cleanup_all(bool remove_published)
{
	struct remote_parent_writer *writer = pending_writers;
	int ret = 0;

	while (writer) {
		struct remote_parent_writer *next = writer->next;

		if (writer->image)
			close_image(writer->image);
		if (writer->dirfd >= 0) {
			if (writer->tmp_created && unlink_coverage(writer->dirfd, writer->tmp_name))
				ret = -1;
			if (remove_published && writer->published &&
			    unlink_coverage(writer->dirfd, writer->final_name))
				ret = -1;
			if (close(writer->dirfd)) {
				pr_perror("Unable to close remote-parent image directory");
				ret = -1;
			}
		}
		xfree(writer);
		writer = next;
	}

	pending_writers = NULL;
	writer_error = false;
	return ret;
}

int remote_parent_finish(bool commit)
{
	struct remote_parent_writer *writer;

	if (!commit)
		return writer_cleanup_all(false);

	for (writer = pending_writers; writer; writer = writer->next)
		remote_parent_writer_close(writer);

	/* No coverage may be published after an image close reported a write error. */
	if (writer_error || bfd_flush_images()) {
		writer_cleanup_all(false);
		return -1;
	}

	for (writer = pending_writers; writer; writer = writer->next) {
		if (linkat(writer->dirfd, writer->tmp_name, writer->dirfd, writer->final_name, 0)) {
			int existing;

			if (errno != EEXIST)
				goto commit_error;
			existing = existing_payload_pagemap(writer);
			if (existing < 0)
				goto rollback;
			if (!existing)
				goto commit_error;

			/*
			 * A page server using the same image directory already owns the
			 * standard pagemap. Its payload-bearing image is authoritative;
			 * the source-side coverage copy is redundant.
			 */
			if (unlink_coverage(writer->dirfd, writer->tmp_name))
				goto rollback;
			writer->tmp_created = false;
			continue;
		}
		writer->published = true;
		if (unlink_coverage(writer->dirfd, writer->tmp_name))
			goto rollback;
		writer->tmp_created = false;
	}


	return writer_cleanup_all(false);

commit_error:
	pr_perror("Unable to commit remote-parent pagemap %s", writer->final_name);
rollback:
	writer_cleanup_all(true);
	return -1;
}

static int open_coverage_image(int dirfd, int fd_type, unsigned long img_id, struct cr_img **out)
{
	PagemapHead *head = NULL;
	struct cr_img *image = NULL;
	struct stat st;
	char name[80];
	u32 magic;
	int fd;
	int ret;

	*out = NULL;
	ret = coverage_name(name, sizeof(name), fd_type, img_id);
	if (ret <= 0)
		return ret;

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		pr_perror("Unable to open remote-parent pagemap %s", name);
		return -1;
	}
	if (fstat(fd, &st)) {
		pr_perror("Unable to stat remote-parent pagemap %s", name);
		close(fd);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		pr_err("Remote-parent pagemap %s is not a regular file\n", name);
		close(fd);
		return -1;
	}

	image = img_from_fd(fd);
	if (!image) {
		close(fd);
		return -1;
	}

	if (read_img(image, &magic) < 0 || magic != IMG_COMMON_MAGIC) {
		pr_err("Remote-parent pagemap %s has invalid common magic\n", name);
		goto err;
	}
	if (read_img(image, &magic) < 0 || magic != imgset_template[fd_type].magic) {
		pr_err("Remote-parent pagemap %s has invalid image magic\n", name);
		goto err;
	}
	if (pb_read_one(image, &head, PB_PAGEMAP_HEAD) < 0) {
		pr_err("Unable to read remote-parent pagemap header\n");
		goto err;
	}
	if (head->pages_id != 0) {
		pagemap_head__free_unpacked(head, NULL);
		close_image(image);
		return 0;
	}

	pagemap_head__free_unpacked(head, NULL);
	*out = image;
	return 1;

err:
	if (head)
		pagemap_head__free_unpacked(head, NULL);
	close_image(image);
	return -1;
}

static void init_compat_entry(PagemapEntry *entry)
{
	if (entry->has_in_parent && entry->in_parent)
		entry->flags |= PE_PARENT;
	else if (!entry->has_flags)
		entry->flags = PE_PRESENT;

	if (!entry->has_nr_pages)
		entry->nr_pages = entry->compat_nr_pages;
}

static int coverage_add(struct remote_parent_coverage *coverage, uint64_t start, uint64_t end)
{
	struct remote_parent_range *last;

	if (coverage->nr_ranges) {
		last = &coverage->ranges[coverage->nr_ranges - 1];
		if (start < last->start) {
			pr_err("Remote-parent pagemap entries are out of order\n");
			return -1;
		}
		if (start <= last->end) {
			if (end > last->end)
				last->end = (unsigned long)end;
			return 0;
		}
	}

	if (coverage->nr_ranges == coverage->capacity) {
		size_t capacity = coverage->capacity ? coverage->capacity * 2 : 16;
		struct remote_parent_range *ranges;

		if (capacity < coverage->capacity || capacity > SIZE_MAX / sizeof(*ranges)) {
			pr_err("Remote-parent pagemap is too large\n");
			return -1;
		}
		ranges = xrealloc(coverage->ranges, capacity * sizeof(*ranges));
		if (!ranges)
			return -1;
		coverage->ranges = ranges;
		coverage->capacity = capacity;
	}

	coverage->ranges[coverage->nr_ranges++] = (struct remote_parent_range){
		.start = (unsigned long)start,
		.end = (unsigned long)end,
	};
	return 0;
}

int remote_parent_coverage_open(int dirfd, int fd_type, unsigned long img_id,
				struct remote_parent_coverage **out)
{
	struct remote_parent_coverage *coverage;
	struct cr_img *image;
	PagemapEntry *entry = NULL;
	int ret;

	*out = NULL;
	ret = open_coverage_image(dirfd, fd_type, img_id, &image);
	if (ret <= 0)
		return ret;

	coverage = xzalloc(sizeof(*coverage));
	if (!coverage) {
		close_image(image);
		return -1;
	}

	while ((ret = pb_read_one_eof(image, &entry, PB_PAGEMAP)) > 0) {
		uint64_t end;

		init_compat_entry(entry);
		if (!entry->nr_pages || (entry->vaddr & (PAGE_SIZE - 1)) || entry->vaddr > ULONG_MAX ||
		    entry->nr_pages > (UINT64_MAX - entry->vaddr) / PAGE_SIZE) {
			pr_err("Invalid remote-parent pagemap entry\n");
			goto err_entry;
		}
		if ((entry->flags & (PE_PRESENT | PE_PARENT)) == (PE_PRESENT | PE_PARENT)) {
			pr_err("Remote-parent pagemap entry is both present and inherited\n");
			goto err_entry;
		}

		end = entry->vaddr + entry->nr_pages * PAGE_SIZE;
		if (end > ULONG_MAX) {
			pr_err("Remote-parent pagemap entry exceeds address space\n");
			goto err_entry;
		}
		if (entry->flags & (PE_PRESENT | PE_PARENT)) {
			if (coverage_add(coverage, entry->vaddr, end))
				goto err_entry;
		}

		pagemap_entry__free_unpacked(entry, NULL);
		entry = NULL;
	}
	if (ret < 0)
		goto err;

	close_image(image);
	*out = coverage;
	return 1;

err_entry:
	pagemap_entry__free_unpacked(entry, NULL);
err:
	close_image(image);
	remote_parent_coverage_close(coverage);
	return -1;
}

int remote_parent_coverage_exists(int dirfd, int fd_type, unsigned long img_id)
{
	struct remote_parent_coverage *coverage = NULL;
	int ret;

	ret = remote_parent_coverage_open(dirfd, fd_type, img_id, &coverage);
	if (ret > 0)
		remote_parent_coverage_close(coverage);
	return ret;
}

bool remote_parent_coverage_contains(const struct remote_parent_coverage *coverage, unsigned long vaddr,
				     unsigned long len)
{
	unsigned long end;
	size_t lo = 0;
	size_t hi;

	if (!coverage || !len || len > ULONG_MAX - vaddr)
		return false;

	end = vaddr + len;
	hi = coverage->nr_ranges;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const struct remote_parent_range *range = &coverage->ranges[mid];

		if (range->end <= vaddr)
			lo = mid + 1;
		else
			hi = mid;
	}

	return lo < coverage->nr_ranges && coverage->ranges[lo].start <= vaddr && coverage->ranges[lo].end >= end;
}

void remote_parent_coverage_close(struct remote_parent_coverage *coverage)
{
	if (!coverage)
		return;

	xfree(coverage->ranges);
	xfree(coverage);
}

