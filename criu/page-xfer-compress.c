#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <lz4.h>

#include "int.h"
#include "common/config.h"
#include "page-xfer.h"
#include "xmalloc.h"
#include "log.h"

#define COMPRESS_CHUNK_SIZE (64 * 1024)
#define LZ4_HEADER_MAGIC    0x12345678

struct chunk_header {
	u32 magic;
	u32 compressed_size;
	u32 original_size;
};

struct compress_xfer_data {
	int (*orig_write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	int (*orig_write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	void (*orig_close)(struct page_xfer *self);

	char *raw_buf;
	char *comp_buf;
	unsigned long buf_cursor;
	unsigned long max_comp_size;
};

static int flush_buffer(struct page_xfer *xfer);

static int send_buf_to_xfer(struct page_xfer *xfer, void *buf, u32 len)
{
	struct compress_xfer_data *data = (struct compress_xfer_data *)xfer->priv;
	int tmp_pipe[2];
	int ret;
	int written = 0;

	if (pipe(tmp_pipe) < 0) {
		pr_perror("COMPRESS: Can't create temp pipe");
		return -1;
	}

	while (written < len) {
		ret = write(tmp_pipe[1], (char *)buf + written, len - written);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("COMPRESS: Write to temp pipe failed");
			close(tmp_pipe[0]);
			close(tmp_pipe[1]);
			return -1;
		}
		written += ret;
	}

	ret = data->orig_write_pages(xfer, tmp_pipe[0], len);

	close(tmp_pipe[0]);
	close(tmp_pipe[1]);

	return ret;
}
static int compress_write_pages(struct page_xfer *xfer, int pipe, unsigned long len)
{
	struct compress_xfer_data *data = (struct compress_xfer_data *)xfer->priv;
	ssize_t ret;
	unsigned long processed = 0;
	unsigned long to_read = 0;
	unsigned long chunk_read_total = 0;

	while (processed < len) {
		unsigned long space_left = COMPRESS_CHUNK_SIZE - data->buf_cursor;

		if (space_left == 0) {
			if (flush_buffer(xfer))
				return -1;
			continue;
		}

		to_read = len - processed;
		if (to_read > space_left)
			to_read = space_left;

		while (chunk_read_total < to_read) {
			ret = read(pipe,
				   data->raw_buf + data->buf_cursor + chunk_read_total,
				   to_read - chunk_read_total);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				pr_perror("COMPRESS: Failed to read from input pipe");
				return -1;
			}
			if (ret == 0) {
				pr_err("COMPRESS: Unexpected EOF from pipe\n");
				return -1;
			}
			chunk_read_total += ret;
		}

		data->buf_cursor += chunk_read_total;
		processed += chunk_read_total;
	}

	return 0;
}

static int flush_buffer(struct page_xfer *xfer)
{
	struct compress_xfer_data *data = (struct compress_xfer_data *)xfer->priv;
	struct chunk_header header;
	int c_size;

	if (data->buf_cursor == 0)
		return 0;

	pr_info("COMPRESS: Flushing buffer... Raw: %lu bytes\n", data->buf_cursor);

	c_size = LZ4_compress_default(data->raw_buf, data->comp_buf,
				      (int)data->buf_cursor, (int)data->max_comp_size);
	if (c_size <= 0) {
		pr_err("COMPRESS: LZ4 failed\n");
		return -1;
	}

	header.magic = LZ4_HEADER_MAGIC;
	header.compressed_size = (u32)c_size;
	header.original_size = (u32)data->buf_cursor;

	if (send_buf_to_xfer(xfer, &header, sizeof(header)))
		return -1;

	if (send_buf_to_xfer(xfer, data->comp_buf, c_size))
		return -1;

	pr_info("COMPRESS: Wrote block. %lu -> %d\n", data->buf_cursor, c_size);

	data->buf_cursor = 0;
	return 0;
}

static int compress_write_pagemap(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct compress_xfer_data *data = (struct compress_xfer_data *)xfer->priv;
	return data->orig_write_pagemap(xfer, iov, flags);
}

static void compress_close(struct page_xfer *xfer)
{
	struct compress_xfer_data *data = (struct compress_xfer_data *)xfer->priv;

	pr_info("COMPRESS: Closing...\n");
	if (data->buf_cursor > 0)
		flush_buffer(xfer);

	if (data->orig_close)
		data->orig_close(xfer);

	if (data->raw_buf)
		xfree(data->raw_buf);
	if (data->comp_buf)
		xfree(data->comp_buf);
	xfree(data);
}

int open_page_compress_xfer(struct page_xfer *xfer)
{
	struct compress_xfer_data *data;

	data = xmalloc(sizeof(*data));
	if (!data)
		return -1;

	data->raw_buf = xmalloc(COMPRESS_CHUNK_SIZE);
	data->max_comp_size = LZ4_compressBound(COMPRESS_CHUNK_SIZE);
	data->comp_buf = xmalloc(data->max_comp_size);
	data->buf_cursor = 0;

	if (!data->raw_buf || !data->comp_buf) {
		xfree(data);
		return -1;
	}

	data->orig_write_pages = xfer->write_pages;
	data->orig_write_pagemap = xfer->write_pagemap;
	data->orig_close = xfer->close;

	xfer->priv = data;
	xfer->write_pages = compress_write_pages;
	xfer->write_pagemap = compress_write_pagemap;
	xfer->close = compress_close;

	return 0;
}