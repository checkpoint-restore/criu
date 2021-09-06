#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>

#include "int.h"
#include "log.h"
#include "common/bug.h"
#include "bfd.h"
#include "common/list.h"
#include "util.h"
#include "xmalloc.h"
#include "page.h"

#undef LOG_PREFIX
#define LOG_PREFIX "bfd: "

/* multiple files can have the same name without any side effects */
#define RB_NAME "/tmp/rb_criu"

/*
 * Kernel doesn't produce more than one page of
 * date per one read call on proc files.
 */
#define RB_BUFSIZE (PAGE_SIZE)
#define BUFBATCH (16)
#define RB_SIZE (RB_BUFSIZE * 2)

#define rb_read_address(rb) (rb->mem + rb->read)
#define rb_write_address(rb) (rb->mem + rb->write)

struct rb_buffer {
    unsigned long size;
    unsigned long write;
    unsigned long read;
    struct list_head l;
    void *mem;
};

static LIST_HEAD(bufs);

/* ring buffer api */

/* rb->size should be exp of 2 */
static inline void rb_write_advance(struct rb_buffer *rb, unsigned long counts)
{
    rb->write = (rb->write + counts) & (rb->size - 1);
}

static inline void rb_read_advance(struct rb_buffer *rb, unsigned long counts)
{
    rb->read = (rb->read + counts) & (rb->size - 1);
}

static inline unsigned long rb_useful_bytes(struct rb_buffer *rb)
{
    return (rb->write - rb->read + rb->size) & (rb->size - 1);
}

static inline unsigned long rb_free_bytes(struct rb_buffer *rb)
{
    /* full is not allowed */
    return rb->size - rb_useful_bytes(rb) - 1;
}

static int buf_get(struct bfd *f)
{
    struct rb_buffer *rb_data;
    int memfd = -1, ret, i;
    void *address, *map_address = NULL;

    if (list_empty(&bufs)) {
        memfd = memfd_create(RB_NAME, 0);
        if (memfd == -1) {
            ret = -errno;
            pr_err("Create temp file from memory failed\n");
            goto err_out;
        }

        ret = ftruncate(memfd, BUFBATCH * RB_SIZE);
        if (ret == -1) {
            ret = -errno;
            pr_err("Ftruncate file failed\n");
            goto err_out;
        }

        for (i = 0; i < BUFBATCH; i++) {
			rb_data = xmalloc(sizeof(*rb_data));
			if (!rb_data) {
                ret = -1;
				pr_err("No buffer for ring buffer data\n");
                goto err_out;
			}
            
            map_address = mmap(NULL, RB_SIZE << 1, PROT_NONE,
                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (map_address == MAP_FAILED) {
                ret = -errno;
                pr_err("Mmap data failed\n");
                goto err_out;
            }

            address = mmap(map_address, RB_SIZE, PROT_READ | PROT_WRITE,
                MAP_FIXED | MAP_SHARED, memfd, i * RB_SIZE);
            if (address != map_address) {
                ret = -EFAULT;
                pr_err("Unable to get fixed mmap address \n");
                goto err_out;
            }

            address = mmap(map_address + RB_SIZE, RB_SIZE, PROT_READ | PROT_WRITE,
                MAP_FIXED | MAP_SHARED, memfd, i * RB_SIZE);
            if (address != map_address + RB_SIZE) {
                ret = -EFAULT;
                pr_err("Unable to get fixed mmap address \n");
                goto err_out;
            }

            rb_data->read = 0;
            rb_data->write = 0;
            rb_data->size = RB_SIZE;
            rb_data->mem = map_address;
            list_add_tail(&rb_data->l, &bufs);
        }
        /* since we have mmap it, it is safe to close it */
        close(memfd);
        memfd = -1;
    }

    rb_data = list_first_entry(&bufs, struct rb_buffer, l);
    list_del_init(&rb_data->l);
    f->rb_data = rb_data;
    f->rb_data->read = f->rb_data->write = 0;
    return 0;

err_out:
    if (map_address != NULL) {
        munmap(map_address, RB_SIZE << 1);
    }
    return ret;
}

static void buf_put(struct bfd *f)
{
    /*
	 * Don't unmap buffer back, it will get reused
	 * by next bfdopen call
	 */
	list_add(&f->rb_data->l, &bufs);
    f->rb_data->read = f->rb_data->write = 0;
    f->rb_data = NULL;
}

static int bfdopen(struct bfd *f, bool writable)
{
    if (buf_get(f)) {
        close_safe(&f->fd);
        return -1;
    }

    f->writable = writable;
    return 0;
}

int bfdopenr(struct bfd *f)
{
	return bfdopen(f, false);
}

int bfdopenw(struct bfd *f)
{
	return bfdopen(f, true);
}

static int bflush(struct bfd *f);
static bool flush_failed = false;

int bfd_flush_images(void)
{
	return flush_failed ? -1 : 0;
}

void bclose(struct bfd *f)
{
	if (bfd_buffered(f)) {
		if (f->writable && bflush(f) < 0) {
			/*
			 * This is to propagate error up. It's
			 * hardly possible by returning and
			 * checking it, but setting a static
			 * flag, failing further bfdopen-s and
			 * checking one at the end would work.
			 */
			flush_failed = true;
			pr_perror("Error flushing image");
		}
		buf_put(f);
	}
	close_safe(&f->fd);
}

static int brefill(struct bfd *f)
{
    struct rb_buffer *rb = f->rb_data;
    char *write_addr = rb_write_address(rb);
    unsigned long free_size = rb_free_bytes(rb);
    int ret;

    ret = read_all(f->fd, write_addr, free_size);
    if (ret < 0) {
        pr_perror("Error reading file");
        return -1;
    }

    rb_write_advance(rb, ret);
    return ret;
}

char *breadline(struct bfd *f)
{
	return breadchr(f, '\n');
}

char *breadchr(struct bfd *f, char c)
{
    char *read_addr, *write_addr;
    struct rb_buffer *rb = f->rb_data;
    unsigned long useful_size, free_size;
    ssize_t tmp;

    write_addr = rb_write_address(rb);
    free_size = rb_free_bytes(rb);

    /* free_size is at least 2 * RB_BUFSIZE */
    if (free_size >= RB_BUFSIZE) {
        tmp = read_all(f->fd, write_addr, free_size);
        if (tmp < 0) {
            pr_err("Read failed\n");
            return ERR_PTR(-EIO);
        }
        rb_write_advance(rb, tmp);
    }

    useful_size = rb_useful_bytes(rb);
    read_addr = rb_read_address(rb);

    /* After read still get 0, means no more data */
    if (useful_size == 0) {
        return NULL;
    }

    /* it is always safe to do this since buffer is not full */
    read_addr[useful_size] = c;

    read_addr = strchrnul(read_addr, c);

    if (*read_addr == c)
        *read_addr = '\0';
    else {
        pr_err("No %c found\n", c);
        return ERR_PTR(-EIO); // not valid
    }

	read_addr = rb_read_address(rb);
    rb_read_advance(rb, strlen(read_addr) + 1);
    return read_addr;
}

static int bflush(struct bfd *f)
{
	struct rb_buffer *rb = f->rb_data;
    unsigned long useful_size = rb_useful_bytes(rb);
    char *read_addr = rb_read_address(rb);
	int ret;

	if (!useful_size)
		return 0;

	ret = write_all(f->fd, read_addr, useful_size);
	if (ret != useful_size)
		return -1;

	rb_read_advance(rb, useful_size);
	return 0;
}

static int __bwrite(struct bfd *f, const void *buf, int size)
{
	struct rb_buffer *rb = f->rb_data;

	if (size > rb_free_bytes(rb)) {
		int ret;
		ret = bflush(f);
		if (ret < 0)
			return ret;
	}

	/* after flush, free bytes should be size - 1 */
    if (size >= rb->size)
		return write_all(f->fd, buf, size);

	memcpy(rb_write_address(rb), buf, size);
	rb_write_advance(rb, size);
	return size;
}

int bwrite(struct bfd *f, const void *buf, int size)
{
	if (!bfd_buffered(f))
		return write_all(f->fd, buf, size);

	return __bwrite(f, buf, size);
}

int bwritev(struct bfd *f, const struct iovec *iov, int cnt)
{
	int i, written = 0;

	if (!bfd_buffered(f)) {
		/*
		 * FIXME writev() should be called again if writev() writes
		 * less bytes than requested.
		 */
		return writev(f->fd, iov, cnt);
	}

	for (i = 0; i < cnt; i++) {
		int ret;

		ret = __bwrite(f, (const void *)iov[i].iov_base, iov[i].iov_len);
		if (ret < 0)
			return ret;

		written += ret;
		if (ret < iov[i].iov_len)
			break;
	}

	return written;
}

int bread(struct bfd *f, void *buf, int size)
{
	struct rb_buffer *rb = f->rb_data;
	int more = 1, filled = 0;
    char *read_addr = rb_read_address(rb);
    unsigned long useful_bytes = rb_useful_bytes(rb);

	if (!bfd_buffered(f))
		return read_all(f->fd, buf, size);

	while (more > 0) {
		int chunk;

		chunk = size - filled;
		if (chunk > useful_bytes)
			chunk = useful_bytes;

		if (chunk) {
			memcpy(buf + filled, read_addr, chunk);
			rb_read_advance(rb, chunk);
            read_addr = rb_read_address(rb);
            useful_bytes = rb_useful_bytes(rb);
			filled += chunk;
		}

		if (filled < size)
			more = brefill(f);
		else {
			BUG_ON(filled > size);
			more = 0;
		}
	}

	return more < 0 ? more : filled;
}