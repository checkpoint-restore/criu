#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cr_options.h"
#include "image.h"
#include "log.h"
#include "page-xfer.h"
#include "remote-parent.h"
#include "servicefd.h"
#include "util.h"

#define REMOTE_PARENT_MAGIC   0x52504352U
#define REMOTE_PARENT_VERSION 1U

/*
 * Source-side metadata used between pre-dump and final dump.
 * It is not part of the restore image ABI.
 */
struct remote_parent_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t fd_type;
	uint32_t reserved;
	uint64_t img_id;
};

struct remote_parent_disk_range {
	uint64_t vaddr;
	uint64_t nr_pages;
};

struct remote_parent_range {
	unsigned long start;
	unsigned long end;
};

struct remote_parent_coverage {
	struct remote_parent_range *ranges;
	size_t nr_ranges;
};

struct remote_parent_writer {
	int fd;
	int dirfd;
	char tmp_name[96];
	char final_name[80];
	bool have_pending;
	bool published;
	bool tmp_created;
	uint64_t pending_vaddr;
	uint64_t pending_nr_pages;
	struct remote_parent_writer *next;
};

static struct remote_parent_writer *pending_writers;
static unsigned long writer_sequence;
static bool writer_error;

static int coverage_name(char *buf, size_t size, int fd_type, unsigned long img_id)
{
	const char *kind;
	int ret;

	if (fd_type == CR_FD_PAGEMAP)
		kind = "pagemap";
	else if (fd_type == CR_FD_SHMEM_PAGEMAP)
		kind = "shmem";
	else
		return 0;

	ret = snprintf(buf, size, "remote-parent-%s-%lu.img", kind, img_id);
	if (ret < 0 || (size_t)ret >= size) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return 1;
}

static int writer_flush_pending(struct remote_parent_writer *writer)
{
	struct remote_parent_disk_range range;

	if (!writer->have_pending)
		return 0;

	range.vaddr = writer->pending_vaddr;
	range.nr_pages = writer->pending_nr_pages;
	if (write_all(writer->fd, &range, sizeof(range)) != (ssize_t)sizeof(range)) {
		pr_perror("Unable to write remote-parent coverage");
		writer_error = true;
		return -1;
	}

	writer->have_pending = false;
	return 0;
}

int remote_parent_writer_open(int fd_type, unsigned long img_id, struct remote_parent_writer **out)
{
	struct remote_parent_disk_header header = {
		.magic = REMOTE_PARENT_MAGIC,
		.version = REMOTE_PARENT_VERSION,
		.fd_type = fd_type,
		.img_id = img_id,
	};
	struct remote_parent_writer *writer;
	int base_fd;
	int ret;

	*out = NULL;
	if (opts.mode != CR_PRE_DUMP)
		return 0;

	writer = xzalloc(sizeof(*writer));
	if (!writer) {
		writer_error = true;
		return -1;
	}

	writer->fd = -1;
	writer->dirfd = -1;

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

	writer->fd = openat(writer->dirfd, writer->tmp_name,
			    O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (writer->fd < 0) {
		pr_perror("Unable to create remote-parent coverage %s", writer->tmp_name);
		goto err;
	}

	writer->tmp_created = true;

	if (write_all(writer->fd, &header, sizeof(header)) != (ssize_t)sizeof(header)) {
		pr_perror("Unable to write remote-parent coverage header");
		goto err;
	}

	writer->next = pending_writers;
	pending_writers = writer;
	*out = writer;
	return 0;

err:
	/* An earlier writer must not be published after this open failed. */
	writer_error = true;
	if (writer->fd >= 0)
		close(writer->fd);
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
	uint64_t vaddr;
	uint64_t nr_pages;
	uint64_t end;
	uint64_t pending_end;

	if (!writer || !(flags & (PE_PRESENT | PE_PARENT)))
		return 0;

	if (!iov->iov_len || iov->iov_len % PAGE_SIZE) {
		pr_err("Invalid remote-parent coverage length %zu\n", iov->iov_len);
		goto err;
	}

	vaddr = (uintptr_t)iov->iov_base;
	nr_pages = iov->iov_len / PAGE_SIZE;
	if ((vaddr & (PAGE_SIZE - 1)) || nr_pages > (UINT64_MAX - vaddr) / PAGE_SIZE) {
		pr_err("Invalid remote-parent coverage range at %#" PRIx64 "\n", vaddr);
		goto err;
	}
	end = vaddr + nr_pages * PAGE_SIZE;

	if (writer->have_pending) {
		pending_end = writer->pending_vaddr + writer->pending_nr_pages * PAGE_SIZE;
		if (vaddr < writer->pending_vaddr) {
			pr_err("Out-of-order remote-parent coverage at %#" PRIx64 "\n", vaddr);
			goto err;
		}
		if (vaddr <= pending_end) {
			if (end > pending_end)
				writer->pending_nr_pages = (end - writer->pending_vaddr) / PAGE_SIZE;
			return 0;
		}
		if (writer_flush_pending(writer))
			return -1;
	}

	writer->pending_vaddr = vaddr;
	writer->pending_nr_pages = nr_pages;
	writer->have_pending = true;
	return 0;

err:
	writer_error = true;
	return -1;
}

void remote_parent_writer_close(struct remote_parent_writer *writer)
{
	if (!writer || writer->fd < 0)
		return;

	writer_flush_pending(writer);
	if (close(writer->fd)) {
		pr_perror("Unable to close remote-parent coverage");
		writer_error = true;
	}
	writer->fd = -1;
}

static int unlink_coverage(int dirfd, const char *name)
{
	if (!unlinkat(dirfd, name, 0) || errno == ENOENT)
		return 0;

	pr_perror("Unable to remove remote-parent coverage %s", name);
	return -1;
}

static int writer_cleanup_all(bool remove_published)
{
	struct remote_parent_writer *writer = pending_writers;
	int ret = 0;

	while (writer) {
		struct remote_parent_writer *next = writer->next;

		if (writer->fd >= 0 && close(writer->fd)) {
			pr_perror("Unable to close remote-parent coverage");
			ret = -1;
		}
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

	if (writer_error) {
		writer_cleanup_all(false);
		return -1;
	}

	for (writer = pending_writers; writer; writer = writer->next) {
		if (linkat(writer->dirfd, writer->tmp_name, writer->dirfd, writer->final_name, 0)) {
			pr_perror("Unable to commit remote-parent coverage %s", writer->final_name);
			goto rollback;
		}
		writer->published = true;
		if (unlink_coverage(writer->dirfd, writer->tmp_name))
			goto rollback;
		writer->tmp_created = false;
	}

	return writer_cleanup_all(false);

rollback:
	writer_cleanup_all(true);
	return -1;
}

static int coverage_file_open(int dirfd, int fd_type, unsigned long img_id, int *fd_out, size_t *nr_ranges)
{
	struct remote_parent_disk_header header;
	struct stat st;
	uintmax_t payload;
	uintmax_t count;
	char name[80];
	int fd;
	int ret;

	*fd_out = -1;
	*nr_ranges = 0;

	ret = coverage_name(name, sizeof(name), fd_type, img_id);
	if (ret <= 0)
		return ret;

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		pr_perror("Unable to open remote-parent coverage %s", name);
		return -1;
	}

	if (fstat(fd, &st)) {
		pr_perror("Unable to stat remote-parent coverage %s", name);
		goto err;
	}
	if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(header)) {
		pr_err("Malformed remote-parent coverage %s\n", name);
		goto err;
	}

	payload = (uintmax_t)(st.st_size - sizeof(header));
	if (payload % sizeof(struct remote_parent_disk_range)) {
		pr_err("Malformed remote-parent coverage %s\n", name);
		goto err;
	}
	count = payload / sizeof(struct remote_parent_disk_range);
	if (count > SIZE_MAX) {
		pr_err("Remote-parent coverage %s is too large\n", name);
		goto err;
	}

	if (read_all(fd, &header, sizeof(header)) != (ssize_t)sizeof(header)) {
		pr_perror("Unable to read remote-parent coverage header");
		goto err;
	}
	if (header.magic != REMOTE_PARENT_MAGIC || header.version != REMOTE_PARENT_VERSION ||
	    header.fd_type != (uint32_t)fd_type || header.reserved || header.img_id != (uint64_t)img_id) {
		pr_err("Remote-parent coverage %s has an incompatible header\n", name);
		goto err;
	}

	*fd_out = fd;
	*nr_ranges = (size_t)count;
	return 1;

err:
	close(fd);
	return -1;
}

int remote_parent_coverage_open(int dirfd, int fd_type, unsigned long img_id,
				struct remote_parent_coverage **out)
{
	struct remote_parent_disk_range disk;
	struct remote_parent_coverage *coverage;
	size_t nr_disk;
	size_t i;
	int fd;
	int ret;

	*out = NULL;
	ret = coverage_file_open(dirfd, fd_type, img_id, &fd, &nr_disk);
	if (ret <= 0)
		return ret;

	coverage = xzalloc(sizeof(*coverage));
	if (!coverage)
		goto err_fd;

	if (nr_disk > SIZE_MAX / sizeof(*coverage->ranges)) {
		pr_err("Remote-parent coverage is too large\n");
		goto err;
	}
	if (nr_disk) {
		coverage->ranges = xmalloc(nr_disk * sizeof(*coverage->ranges));
		if (!coverage->ranges)
			goto err;
	}

	for (i = 0; i < nr_disk; i++) {
		struct remote_parent_range *last;
		uint64_t end;

		if (read_all(fd, &disk, sizeof(disk)) != (ssize_t)sizeof(disk)) {
			pr_perror("Unable to read remote-parent coverage range");
			goto err;
		}
		if (!disk.nr_pages || (disk.vaddr & (PAGE_SIZE - 1)) || disk.vaddr > ULONG_MAX ||
		    disk.nr_pages > (UINT64_MAX - disk.vaddr) / PAGE_SIZE) {
			pr_err("Invalid remote-parent coverage range\n");
			goto err;
		}

		end = disk.vaddr + disk.nr_pages * PAGE_SIZE;
		if (end > ULONG_MAX) {
			pr_err("Remote-parent coverage range exceeds address space\n");
			goto err;
		}

		if (!coverage->nr_ranges) {
			coverage->ranges[coverage->nr_ranges++] = (struct remote_parent_range){
				.start = (unsigned long)disk.vaddr,
				.end = (unsigned long)end,
			};
			continue;
		}

		last = &coverage->ranges[coverage->nr_ranges - 1];
		if (disk.vaddr < last->start) {
			pr_err("Remote-parent coverage ranges are out of order\n");
			goto err;
		}
		if (disk.vaddr <= last->end) {
			if (end > last->end)
				last->end = (unsigned long)end;
			continue;
		}

		coverage->ranges[coverage->nr_ranges++] = (struct remote_parent_range){
			.start = (unsigned long)disk.vaddr,
			.end = (unsigned long)end,
		};
	}

	close(fd);
	*out = coverage;
	return 1;

err:
	remote_parent_coverage_close(coverage);
err_fd:
	close(fd);
	return -1;
}

int remote_parent_coverage_exists(int dirfd, int fd_type, unsigned long img_id)
{
	size_t nr_ranges;
	int fd;
	int ret;

	ret = coverage_file_open(dirfd, fd_type, img_id, &fd, &nr_ranges);
	if (ret > 0)
		close(fd);
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
