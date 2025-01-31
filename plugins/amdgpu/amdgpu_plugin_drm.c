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
#include "files.h"

#include "criu-amdgpu.pb-c.h"

#include <xf86drm.h>
#include <libdrm/amdgpu.h>

#include "xmalloc.h"
#include "criu-log.h"
#include "amdgpu_drm.h"
#include "amdgpu_plugin_drm.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_topology.h"


#include "util.h"
#include "common/scm.h"

int get_gem_handle(amdgpu_device_handle h_dev, int dmabuf_fd)
{
	uint32_t handle;
	int fd = amdgpu_device_get_fd(h_dev);

	if (dmabuf_fd == -1) {
		return -1;
	}

	drmPrimeFDToHandle(fd, dmabuf_fd, &handle);

	return handle;
}

int drmIoctl(int fd, unsigned long request, void *arg)
{
	int ret, max_retries = 200;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && max_retries-- > 0 && (errno == EINTR || errno == EAGAIN));

	if (ret == -1 && errno == EBADF)
		/* In case pthread_atfork didn't catch it, this will
		 * make any subsequent hsaKmt calls fail in CHECK_KFD_OPEN.
		 */
		pr_perror("KFD file descriptor not valid in this process");
	return ret;
}

static int allocate_bo_entries(CriuRenderNode *e, int num_bos)
{
	e->bo_entries = xmalloc(sizeof(DrmBoEntry *) * num_bos);
	if (!e->bo_entries) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_bos; i++) {
		DrmBoEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		drm_bo_entry__init(entry);

		e->bo_entries[i] = entry;
		e->n_bo_entries++;
	}
	return 0;
}

static void free_e(CriuRenderNode *e)
{
	for (int i = 0; i < e->n_bo_entries; i++) {
		if (e->bo_entries[i])
			xfree(e->bo_entries[i]);
	}

	xfree(e);
}

int amdgpu_plugin_drm_handle_device_vma(int fd, const struct stat *st)
{
	char path[PATH_MAX];
	struct stat drm;
	int ret = 0;

	snprintf(path, sizeof(path), AMDGPU_DRM_DEVICE, DRM_FIRST_RENDER_NODE);
	ret = stat(path, &drm);
	if (ret == -1) {
		pr_err("Error in getting stat for: %s\n", path);
		return ret;
	}

	if ((major(st->st_rdev) != major(drm.st_rdev)) ||
		(minor(st->st_rdev) < minor(drm.st_rdev)) ||
		(minor(st->st_rdev) > DRM_LAST_RENDER_NODE)) {
		pr_err("Can't handle VMA mapping of input device\n");
		return -ENOTSUP;
	}

	pr_debug("AMD DRI(maj,min) = %d:%d VMA Device FD(maj,min) = %d:%d\n",
			 major(drm.st_rdev), minor(drm.st_rdev),
			 major(st->st_rdev), minor(st->st_rdev));

	return 0;
}

static int restore_bo_contents_drm(int drm_render_minor, pid_t pid, int drm_fd, uint64_t num_of_bos, struct drm_amdgpu_criu_bo_bucket *bo_buckets)
{
	size_t image_size = 0, total_bo_size = 0, max_bo_size = 0, buffer_size;
	struct amdgpu_gpu_info gpu_info = { 0 };
	amdgpu_device_handle h_dev;
	uint64_t max_copy_size;
	uint32_t major, minor;
	FILE *bo_contents_fp = NULL;
	void *buffer = NULL;
	char img_path[40];
	int num_bos = 0;
	int i, ret = 0;

	ret = amdgpu_device_initialize(drm_fd, &major, &minor, &h_dev);
	if (ret) {
		pr_perror("failed to initialize device");
		goto exit;
	}
	plugin_log_msg("libdrm initialized successfully\n");

	ret = amdgpu_query_gpu_info(h_dev, &gpu_info);
	if (ret) {
		pr_perror("failed to query gpuinfo via libdrm");
		goto exit;
	}

	max_copy_size = (gpu_info.family_id >= AMDGPU_FAMILY_AI) ? SDMA_LINEAR_COPY_MAX_SIZE :
								   SDMA_LINEAR_COPY_MAX_SIZE - 1;

	for (i = 0; i < num_of_bos; i++) {
		if (bo_buckets[i].preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)) {
			total_bo_size += bo_buckets[i].size;

			if (bo_buckets[i].size > max_bo_size)
				max_bo_size = bo_buckets[i].size;
		}
	}

	buffer_size = max_bo_size;

	posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (!buffer) {
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < num_of_bos; i++) {

		if (!(bo_buckets[i].preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)))
			continue;

		if (bo_buckets[i].addr == -1)
			continue;

		num_bos++;

		snprintf(img_path, sizeof(img_path), IMG_DRM_PAGES_FILE, pid, drm_render_minor, i);
		bo_contents_fp = open_img_file(img_path, false, &image_size);

		ret = sdma_copy_bo(bo_buckets[i].dmabuf_fd, bo_buckets[i].size, bo_contents_fp, buffer, buffer_size, h_dev, max_copy_size,
				   SDMA_OP_VRAM_WRITE, true);
		if (ret) {
			pr_err("Failed to fill the BO using sDMA: bo_buckets[%d]\n", i);
			break;
		}
		plugin_log_msg("** Successfully filled the BO using sDMA: bo_buckets[%d] **\n", i);

		if (bo_contents_fp)
			fclose(bo_contents_fp);
	}

exit:
	for (int i = 0; i < num_of_bos; i++) {
		if (bo_buckets[i].dmabuf_fd != KFD_INVALID_FD)
			close(bo_buckets[i].dmabuf_fd);
	}

	xfree(buffer);

	amdgpu_device_deinitialize(h_dev);
	return ret;
}

int amdgpu_plugin_drm_dump_file(int fd, int id, struct stat *drm)
{
	CriuRenderNode *rd = NULL;
	char path[PATH_MAX];
	unsigned char *buf;
	int minor;
	int len;
	int ret;
	struct drm_amdgpu_criu_args args = {0};
	size_t image_size;
	struct tp_node *tp_node;

	rd = xmalloc(sizeof(*rd));
	if (!rd) {
		ret = -ENOMEM;
		goto exit;
	}
	criu_render_node__init(rd);

	/* Get the topology node of the DRM device */
	minor = minor(drm->st_rdev);
	rd->drm_render_minor = minor;

	args.op = AMDGPU_CRIU_OP_PROCESS_INFO;
	if (drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_OP, &args) == -1) {
		pr_perror("Failed to call process info ioctl");
		ret = -1;
		goto exit;
	}

	rd->pid = args.pid;
	rd->num_of_bos = args.num_bos;
	rd->num_of_objects = args.num_objs;
	ret = allocate_bo_entries(rd, args.num_bos);
	if (ret)
		goto exit;

	args.bos = (uintptr_t)xzalloc((args.num_bos * sizeof(struct drm_amdgpu_criu_bo_bucket)));
	if (!args.bos) {
		ret = -ENOMEM;
		goto exit;
	}

	args.priv_data = (uintptr_t)xzalloc((args.priv_data_size));
	if (!args.priv_data) {
		ret = -ENOMEM;
		goto exit;
	}

	args.op = AMDGPU_CRIU_OP_CHECKPOINT;
	ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_OP, &args);
	if (ret) {
		pr_perror("Failed to call dumper (process) ioctl");
		goto exit;
	}

	rd->priv_data.data = (void *)args.priv_data;
	rd->priv_data.len = args.priv_data_size;

	for (int i = 0; i < args.num_bos; i++) {
		struct drm_amdgpu_criu_bo_bucket bo_bucket = ((struct drm_amdgpu_criu_bo_bucket *)args.bos)[i];
		uint32_t major, minor;
		amdgpu_device_handle h_dev;
		void *buffer = NULL;
		char img_path[40];
		FILE *bo_contents_fp = NULL;
		DrmBoEntry *boinfo = rd->bo_entries[i];

		boinfo->addr = bo_bucket.addr;
		boinfo->size = bo_bucket.size;
		boinfo->offset = bo_bucket.offset;
		boinfo->alloc_flags = bo_bucket.alloc_flags;
		boinfo->preferred_domains = bo_bucket.preferred_domains;

		ret = amdgpu_device_initialize(fd, &major, &minor, &h_dev);

		snprintf(img_path, sizeof(img_path), IMG_DRM_PAGES_FILE, rd->pid, rd->drm_render_minor, i); //TODO: needs to be unique by process and by device, and recoverable by restore
		bo_contents_fp = open_img_file(img_path, true, &image_size);

		posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), bo_bucket.size);

		ret = sdma_copy_bo(bo_bucket.dmabuf_fd, bo_bucket.size, bo_contents_fp, buffer, bo_bucket.size, h_dev, 0x1000,
				   SDMA_OP_VRAM_READ, false);

		boinfo->handle = get_gem_handle(h_dev, bo_bucket.dmabuf_fd);
		boinfo->is_import = bo_bucket.is_import | shared_bo_has_exporter(boinfo->handle);

		if (bo_bucket.dmabuf_fd != KFD_INVALID_FD)
			close(bo_bucket.dmabuf_fd);

		if (bo_contents_fp)
			fclose(bo_contents_fp);

		ret = amdgpu_device_deinitialize(h_dev);
		if (ret)
			goto exit;
	}
	for (int i = 0; i < args.num_bos; i++) {
		DrmBoEntry *boinfo = rd->bo_entries[i];

		ret = record_shared_bo(boinfo->handle, boinfo->is_import);
		if (ret)
			goto exit;
	}

	tp_node = sys_get_node_by_render_minor(&src_topology, minor);
	if (!tp_node) {
		pr_err("Failed to find a device with minor number = %d\n", minor);
		return -ENODEV;
	}

	/* Get the GPU_ID of the DRM device */
	rd->gpu_id = maps_get_dest_gpu(&checkpoint_maps, tp_node->gpu_id);
	if (!rd->gpu_id) {
		pr_err("Failed to find valid gpu_id for the device = %d\n", rd->gpu_id);
		return -ENODEV;
	}

	len = criu_render_node__get_packed_size(rd);
	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	criu_render_node__pack(rd, buf);

	snprintf(path, sizeof(path), IMG_DRM_FILE, id);
	ret = write_img_file(path, buf, len);

	exit:
	xfree((void *)args.bos);
	xfree((void *)args.priv_data);
	xfree(buf);
	free_e(rd);
	return ret;
}

int amdgpu_plugin_drm_unpause_file(int fd) {
	struct drm_amdgpu_criu_args args = {0};
	int ret = 0;

	args.op = AMDGPU_CRIU_OP_UNPAUSE;
	if (drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_OP, &args) == -1) {
		pr_perror("Failed to call unpause ioctl");
		ret = -1;
		goto exit;
	}

	exit:
	return ret;
}

int amdgpu_plugin_drm_restore_file(int fd, CriuRenderNode *rd)
{
	struct drm_amdgpu_criu_args args = {0};
	int ret = 0;
	bool retry_needed = false;

	args.num_bos = rd->num_of_bos;
	args.num_objs = rd->num_of_objects;
	args.priv_data = (uint64_t)rd->priv_data.data;
	args.priv_data_size = rd->priv_data.len;
	args.bos = (uint64_t)xzalloc(sizeof(struct drm_amdgpu_criu_bo_bucket) * rd->num_of_bos);

	for (int i = 0; i < args.num_bos; i++) {
		struct drm_amdgpu_criu_bo_bucket *bo_bucket = &((struct drm_amdgpu_criu_bo_bucket *)args.bos)[i];
		DrmBoEntry *boinfo = rd->bo_entries[i];
		int dmabuf_fd = -1;

		bo_bucket->addr = boinfo->addr;

		if (work_already_completed(boinfo->handle, rd->drm_render_minor)) {
			bo_bucket->skip = 1;
		} else if (boinfo->handle != -1) {
			if (boinfo->is_import) {
				dmabuf_fd = dmabuf_fd_for_handle(boinfo->handle);
				if (dmabuf_fd == -1) {
					bo_bucket->skip = 1;
					retry_needed = true;
				}
			}
		}

		bo_bucket->is_import = boinfo->is_import;

		bo_bucket->dmabuf_fd = dmabuf_fd;
		bo_bucket->size = boinfo->size;
		bo_bucket->offset = boinfo->offset;
		bo_bucket->alloc_flags = boinfo->alloc_flags;
		bo_bucket->preferred_domains = boinfo->preferred_domains;
	}

	args.op = AMDGPU_CRIU_OP_RESTORE;
	if (drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_OP, &args) == -1) {
		pr_perror("Failed to call restore ioctl");
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < args.num_bos; i++) {
		struct drm_amdgpu_criu_bo_bucket *bo_bucket = &((struct drm_amdgpu_criu_bo_bucket *)args.bos)[i];
		DrmBoEntry *boinfo = rd->bo_entries[i];

		if (!bo_bucket->skip && !work_already_completed(boinfo->handle, rd->drm_render_minor)) {
			ret = record_completed_work(boinfo->handle, rd->drm_render_minor);
			if (ret)
				goto exit;
			if (!boinfo->is_import) {
				serve_out_dmabuf_fd(boinfo->handle, bo_bucket->dmabuf_fd);
			}
		}
	}
	ret = record_completed_work(-1, rd->drm_render_minor);
	if (ret)
		goto exit;

	if (args.num_bos > 0) {

		for (int i = 0; i < args.num_bos; i++) {
			struct drm_amdgpu_criu_bo_bucket *bo_bucket = &((struct drm_amdgpu_criu_bo_bucket *)args.bos)[i];

			if (!bo_bucket->skip)
				ret = save_vma_updates(bo_bucket->offset, bo_bucket->addr, bo_bucket->restored_offset, fd);
			if (ret < 0)
				goto exit;
		}

		ret = restore_bo_contents_drm(rd->drm_render_minor, rd->pid, fd, args.num_bos, (struct drm_amdgpu_criu_bo_bucket *)args.bos);
		if (ret)
			goto exit;
	}


	exit:
	if (ret < 0)
		return ret;

	return retry_needed;
}
