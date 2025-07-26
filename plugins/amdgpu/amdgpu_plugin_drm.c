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
#include "fdstore.h"

#include "criu-amdgpu.pb-c.h"
#define __user
#include "drm.h"

#include <xf86drm.h>
#include <libdrm/amdgpu.h>

#include "xmalloc.h"
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

static int allocate_vm_entries(DrmBoEntry *e, int num_vms)
{
	e->vm_entries = xmalloc(sizeof(DrmVmEntry *) * num_vms);
	if (!e->vm_entries) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_vms; i++) {
		DrmVmEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		drm_vm_entry__init(entry);

		e->vm_entries[i] = entry;
		e->n_vm_entries++;
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

static int restore_bo_contents_drm(int drm_render_minor, CriuRenderNode *rd, int drm_fd, int *dmabufs)
{
	size_t image_size = 0, max_bo_size = 0, buffer_size;
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

	for (i = 0; i < rd->num_of_bos; i++) {
		if (rd->bo_entries[i]->preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)) {
			//total_bo_size += rd->bo_entries[i]->size;

			if (rd->bo_entries[i]->size > max_bo_size)
				max_bo_size = rd->bo_entries[i]->size;
		}
	}

	buffer_size = max_bo_size;

	posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (!buffer) {
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < rd->num_of_bos; i++) {

		if (!(rd->bo_entries[i]->preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)))
			continue;

		if (rd->bo_entries[i]->num_of_vms == 0)
			continue;

		num_bos++;

		snprintf(img_path, sizeof(img_path), IMG_DRM_PAGES_FILE, rd->id, drm_render_minor, i);

		bo_contents_fp = open_img_file(img_path, false, &image_size);

		ret = sdma_copy_bo(dmabufs[i], rd->bo_entries[i]->size, bo_contents_fp, buffer, buffer_size, h_dev, max_copy_size,
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
	for (int i = 0; i < rd->num_of_bos; i++) {
		if (dmabufs[i] != KFD_INVALID_FD)
			close(dmabufs[i]);
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
	size_t image_size;
	struct tp_node *tp_node;
	struct drm_amdgpu_criu_bo_info_args bo_info_args = {0};
	struct drm_amdgpu_criu_bo_bucket *bo_info_buckets;
	int num_bo_buckets;

	rd = xmalloc(sizeof(*rd));
	if (!rd) {
		ret = -ENOMEM;
		goto exit;
	}
	criu_render_node__init(rd);

	/* Get the topology node of the DRM device */
	minor = minor(drm->st_rdev);
	rd->drm_render_minor = minor;
	rd->id = id;

	num_bo_buckets = 8;
	bo_info_buckets = xzalloc(sizeof(struct drm_amdgpu_criu_bo_bucket) * num_bo_buckets);
	bo_info_args.num_bos = num_bo_buckets;
	bo_info_args.bo_buckets = (uintptr_t)bo_info_buckets;

	ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_BO_INFO, &bo_info_args);
	if (ret) {
		pr_perror("Failed to call bo info ioctl");
		goto exit;
	}

	if (bo_info_args.num_bos > num_bo_buckets) {
		num_bo_buckets = bo_info_args.num_bos;
		xfree(bo_info_buckets);
		bo_info_buckets = xzalloc(sizeof(struct drm_amdgpu_criu_bo_bucket) * num_bo_buckets);
		bo_info_args.num_bos = num_bo_buckets;
		bo_info_args.bo_buckets = (uintptr_t)bo_info_buckets;
		ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_BO_INFO, &bo_info_args);
		if (ret) {
			pr_perror("Failed to call bo info ioctl");
			goto exit;
		}
	} else {
		num_bo_buckets = bo_info_args.num_bos;
	}

	rd->num_of_bos = num_bo_buckets;
	ret = allocate_bo_entries(rd, num_bo_buckets);
	if (ret)
		goto exit;

	for (int i = 0; i < num_bo_buckets; i++) {
		int num_vm_buckets = 8;
		struct drm_amdgpu_criu_vm_bucket *vm_info_buckets;
		struct drm_amdgpu_criu_mapping_info_args vm_info_args = {0};
		DrmBoEntry *boinfo = rd->bo_entries[i];
		struct drm_amdgpu_criu_bo_bucket bo_bucket = bo_info_buckets[i];
		union drm_amdgpu_gem_mmap mmap_args = {0};
		int dmabuf_fd;
		uint32_t major, minor;
		amdgpu_device_handle h_dev;
		void *buffer = NULL;
		char img_path[40];
		FILE *bo_contents_fp = NULL;
		int device_fd;

		boinfo->size = bo_bucket.size;
		//boinfo->offset = bo_bucket.offset;

		boinfo->alloc_flags = bo_bucket.alloc_flags;
		boinfo->preferred_domains = bo_bucket.preferred_domains;
		boinfo->handle = bo_bucket.gem_handle;
		boinfo->is_import = (bo_bucket.flags & AMDGPU_CRIU_BO_FLAG_IS_IMPORT)
			|| shared_bo_has_exporter(boinfo->handle);

		//get offset from...
		mmap_args.in.handle = boinfo->handle;

		if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_MMAP, &mmap_args) == -1) {
			pr_perror("Error Failed to call mmap ioctl");
			ret = -1;
			goto exit;
		}

		boinfo->offset = mmap_args.out.addr_ptr;

		vm_info_buckets = xzalloc(sizeof(struct drm_amdgpu_criu_vm_bucket) * num_vm_buckets);
		vm_info_args.gem_handle = bo_bucket.gem_handle;
		vm_info_args.num_mappings = num_vm_buckets;
		vm_info_args.vm_buckets = (uintptr_t)vm_info_buckets;
		ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_MAPPING_INFO, &vm_info_args);
		if (ret) {
			pr_perror("Failed to call vm info ioctl");
			goto exit;
		}

		if (vm_info_args.num_mappings > num_vm_buckets) {
			num_vm_buckets = vm_info_args.num_mappings;
			xfree(vm_info_buckets);
			vm_info_buckets = xzalloc(sizeof(struct drm_amdgpu_criu_vm_bucket) * num_vm_buckets);
			vm_info_args.num_mappings = num_vm_buckets;
			vm_info_args.vm_buckets = (uintptr_t)vm_info_buckets;
			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CRIU_MAPPING_INFO, &vm_info_args);
			if (ret) {
				pr_perror("Failed to call vm info ioctl");
				goto exit;
			}
		} else {
			num_vm_buckets = vm_info_args.num_mappings;
		}

		boinfo->num_of_vms = num_vm_buckets;
		ret = allocate_vm_entries(boinfo, num_vm_buckets);
		if (ret)
			goto exit;

		for (int j = 0; j < num_vm_buckets; j++) {
			DrmVmEntry *vminfo = boinfo->vm_entries[j];

			boinfo->addr = vm_info_buckets[j].start * 0x1000;
			vminfo->start = vm_info_buckets[j].start;
			vminfo->last = vm_info_buckets[j].last;
			vminfo->offset = vm_info_buckets[j].offset;
			vminfo->flags = vm_info_buckets[j].flags;
		}

		ret = amdgpu_device_initialize(fd, &major, &minor, &h_dev);

		device_fd = amdgpu_device_get_fd(h_dev);

		drmPrimeHandleToFD(device_fd, boinfo->handle, 0, &dmabuf_fd);

		snprintf(img_path, sizeof(img_path), IMG_DRM_PAGES_FILE, rd->id, rd->drm_render_minor, i);
		bo_contents_fp = open_img_file(img_path, true, &image_size);

		posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), bo_bucket.size);

		ret = sdma_copy_bo(dmabuf_fd, bo_bucket.size, bo_contents_fp, buffer, bo_bucket.size, h_dev, 0x1000,
				   SDMA_OP_VRAM_READ, false);

		if (dmabuf_fd != KFD_INVALID_FD)
			close(dmabuf_fd);

		if (bo_contents_fp)
			fclose(bo_contents_fp);

		ret = amdgpu_device_deinitialize(h_dev);
		if (ret)
			goto exit;

		xfree(vm_info_buckets);
	}
	xfree(bo_info_buckets);

	for (int i = 0; i < num_bo_buckets; i++) {
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

	xfree(buf);
	exit:
	free_e(rd);
	return ret;
}

int amdgpu_plugin_drm_restore_file(int fd, CriuRenderNode *rd)
{
	int ret = 0;
	bool retry_needed = false;
	uint32_t major, minor;
	amdgpu_device_handle h_dev;
	int device_fd;
	int *dmabufs = xzalloc(sizeof(int) * rd->num_of_bos);

	ret = amdgpu_device_initialize(fd, &major, &minor, &h_dev);
	if (ret) {
		pr_info("Error in init amdgpu device\n");
		goto exit;
	}

	device_fd = amdgpu_device_get_fd(h_dev);

	for (int i = 0; i < rd->num_of_bos; i++) {
		DrmBoEntry *boinfo = rd->bo_entries[i];
		int dmabuf_fd = -1;
		uint32_t handle;
		struct drm_gem_change_handle change_args = {0};
		union drm_amdgpu_gem_mmap mmap_args = {0};
		struct drm_amdgpu_gem_va va_args = {0};

		if (work_already_completed(boinfo->handle, rd->drm_render_minor)) {
			//bo_bucket->addr = -1;
			continue;
		} else if (boinfo->handle != -1) {
			if (boinfo->is_import) {
				dmabuf_fd = fdstore_get(dmabuf_fd_for_handle(boinfo->handle));
				if (dmabuf_fd == -1) {
					continue;
				}
			}
		}

		if (boinfo->is_import) {
			drmPrimeFDToHandle(device_fd, dmabuf_fd, &handle);
		} else {
			union drm_amdgpu_gem_create create_args = {0};

			create_args.in.bo_size = boinfo->size;
			create_args.in.alignment = 0x1000;
			create_args.in.domains = boinfo->preferred_domains;
			create_args.in.domain_flags = boinfo->alloc_flags;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_CREATE, &create_args) == -1) {
				pr_perror("Error Failed to call create ioctl");
				ret = -1;
				goto exit;
			}
			handle = create_args.out.handle;

			drmPrimeHandleToFD(device_fd, handle, 0, &dmabuf_fd);
		}

		change_args.handle = handle;
		change_args.new_handle = boinfo->handle;

		if (drmIoctl(fd, DRM_IOCTL_GEM_CHANGE_HANDLE, &change_args) == -1) {
			pr_perror("Error Failed to call change ioctl");
			ret = -1;
			goto exit;
		}

		if (!boinfo->is_import)
			serve_out_dmabuf_fd(boinfo->handle, dmabuf_fd);

		dmabufs[i] = dmabuf_fd;

		ret = record_completed_work(boinfo->handle, rd->drm_render_minor);
		if (ret)
			goto exit;

		mmap_args.in.handle = boinfo->handle;

		if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_MMAP, &mmap_args) == -1) {
			pr_perror("Error Failed to call mmap ioctl");
			ret = -1;
			goto exit;
		}

		for (int j = 0; j < boinfo->num_of_vms; j++) {
			DrmVmEntry *vminfo = boinfo->vm_entries[j];

			va_args.handle = boinfo->handle;
			va_args.operation = AMDGPU_VA_OP_MAP;
			va_args.flags = vminfo->flags;
			va_args.va_address = vminfo->start * 0x1000;
			va_args.offset_in_bo = vminfo->offset;
			va_args.map_size = (vminfo->last - vminfo->start + 1) * 0x1000;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_VA, &va_args) == -1) {
				pr_perror("Error Failed to call mmap ioctl");
				ret = -1;
				goto exit;
			}

		}

		ret = save_vma_updates(boinfo->offset, boinfo->addr, mmap_args.out.addr_ptr, fd);
		if (ret < 0)
			goto exit;

	}

	if (ret) {
		pr_info("Error in deinit amdgpu device\n");
		goto exit;
	}

	ret = record_completed_work(-1, rd->drm_render_minor);
	if (ret)
		goto exit;

	ret = amdgpu_device_deinitialize(h_dev);

	if (rd->num_of_bos > 0) {
		ret = restore_bo_contents_drm(rd->drm_render_minor, rd, fd, dmabufs);
		if (ret)
			goto exit;
	}

	exit:
	if (ret < 0)
		return ret;
	xfree(dmabufs);

	return retry_needed;
}
