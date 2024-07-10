#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/limits.h>

#include <dirent.h>
#include "common/list.h"

#include <xf86drm.h>
#include <libdrm/amdgpu.h>

#include "criu-plugin.h"
#include "plugin.h"
#include "criu-amdgpu.pb-c.h"

#include "img-streamer.h"
#include "image.h"
#include "cr_options.h"

#include "xmalloc.h"
#include "criu-log.h"
#include "kfd_ioctl.h"
#include "amdgpu_drm.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_topology.h"

/* Tracks number of device files that need to be checkpointed */
static int dev_file_cnt = 0;

/* Helper structures to encode device topology of SRC and DEST platforms */
struct tp_system src_topology;
struct tp_system dest_topology;

/* Helper structures to encode device maps during Checkpoint and Restore operations */
struct device_maps checkpoint_maps;
struct device_maps restore_maps;

bool checkpoint_is_complete()
{
	return (dev_file_cnt == 0);
}

void decrement_checkpoint_count()
{
	dev_file_cnt--;
}

void init_gpu_count(struct tp_system *topo)
{
	if (dev_file_cnt != 0)
		return;

	/* We add ONE to include checkpointing of KFD device */
	dev_file_cnt = 1 + topology_gpu_count(topo);
}

int read_fp(FILE *fp, void *buf, const size_t buf_len)
{
	size_t len_read;

	len_read = fread(buf, 1, buf_len, fp);
	if (len_read != buf_len) {
		pr_err("Unable to read file (read:%ld buf_len:%ld)\n", len_read, buf_len);
		return -EIO;
	}
	return 0;
}

int write_fp(FILE *fp, const void *buf, const size_t buf_len)
{
	size_t len_write;

	len_write = fwrite(buf, 1, buf_len, fp);
	if (len_write != buf_len) {
		pr_err("Unable to write file (wrote:%ld buf_len:%ld)\n", len_write, buf_len);
		return -EIO;
	}
	return 0;
}

/**
 * @brief Open an image file
 *
 * We store the size of the actual contents in the first 8-bytes of
 * the file. This allows us to determine the file size when using
 * criu_image_streamer when fseek and fstat are not available. The
 * FILE * returned is already at the location of the first actual
 * contents.
 *
 * @param path The file path
 * @param write False for read, true for write
 * @param size Size of actual contents
 * @return FILE *if successful, NULL if failed
 */
FILE *open_img_file(char *path, bool write, size_t *size)
{
	FILE *fp = NULL;
	int fd, ret;

	if (opts.stream)
		fd = img_streamer_open(path, write ? O_DUMP : O_RSTR);
	else
		fd = openat(criu_get_image_dir(), path, write ? (O_WRONLY | O_CREAT) : O_RDONLY, 0600);

	if (fd < 0) {
		pr_err("%s: Failed to open for %s\n", path, write ? "write" : "read");
		return NULL;
	}

	fp = fdopen(fd, write ? "w" : "r");
	if (!fp) {
		pr_err("%s: Failed get pointer for %s\n", path, write ? "write" : "read");
		return NULL;
	}

	if (write)
		ret = write_fp(fp, size, sizeof(*size));
	else
		ret = read_fp(fp, size, sizeof(*size));

	if (ret) {
		pr_err("%s:Failed to access file size\n", path);
		fclose(fp);
		return NULL;
	}

	pr_debug("%s:Opened file for %s with size:%ld\n", path, write ? "write" : "read", *size);
	return fp;
}

int read_file(const char *file_path, void *buf, const size_t buf_len)
{
	int ret;
	FILE *fp;

	fp = fopen(file_path, "r");
	if (!fp) {
		pr_err("Cannot fopen %s\n", file_path);
		return -errno;
	}

	ret = read_fp(fp, buf, buf_len);
	fclose(fp); /* this will also close fd */
	return ret;
}


/**
 * @brief Write an image file
 *
 * We store the size of the actual contents in the first 8-bytes of the file. This allows us to
 * determine the file size when using criu_image_streamer when fseek and fstat are not available.
 *
 * @param path The file path
 * @param buf pointer to data to be written
 * @param buf_len size of buf
 * @return 0 if successful. -errno on failure
 */
int write_img_file(char *path, const void *buf, const size_t buf_len)
{
	int ret;
	FILE *fp;
	size_t len = buf_len;

	fp = open_img_file(path, true, &len);
	if (!fp)
		return -errno;

	ret = write_fp(fp, buf, buf_len);
	fclose(fp); /* this will also close fd */
	return ret;
}

void print_kfd_bo_stat(int bo_cnt, struct kfd_criu_bo_bucket *bo_list)
{
	struct kfd_criu_bo_bucket *bo;

	pr_info("\n");
	for (int idx = 0; idx < bo_cnt; idx++) {
		bo = &bo_list[idx];
		pr_info("\n");
		pr_info("%s(), %d. KFD BO Addr: %" PRIx64 " \n", __func__, idx, bo->addr);
		pr_info("%s(), %d. KFD BO Size: %" PRIx64 " \n", __func__, idx, bo->size);
		pr_info("%s(), %d. KFD BO Offset: %" PRIx64 " \n", __func__, idx, bo->offset);
		pr_info("%s(), %d. KFD BO Restored Offset: %" PRIx64 " \n", __func__, idx, bo->restored_offset);
		pr_info("%s(), %d. KFD BO Alloc Flags: %x \n", __func__, idx, bo->alloc_flags);
		pr_info("%s(), %d. KFD BO Gpu ID: %x \n", __func__, idx, bo->gpu_id);
		pr_info("%s(), %d. KFD BO Dmabuf FD: %x \n", __func__, idx, bo->dmabuf_fd);
		pr_info("\n");
	}
	pr_info("\n");
}
