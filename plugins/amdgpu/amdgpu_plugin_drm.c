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

/* Define __user as empty for kernel headers in user-space */
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

	if (drmPrimeFDToHandle(fd, dmabuf_fd, &handle))
		return -1;

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

static int allocate_context_entries(CriuRenderNode *e, unsigned long num_contexts)
{
	e->contexts = xmalloc(sizeof(DrmContextEntry *) * num_contexts);
	if (!e->contexts) {
		pr_err("Failed to allocate context list\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_contexts; i++) {
		DrmContextEntry *context = xzalloc(sizeof(*context));

		if (!context) {
			pr_err("Failed to allocate context info\n");
			return -ENOMEM;
		}

		drm_context_entry__init(context);

		e->contexts[i] = context;
		e->n_contexts++;
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
	xfree(e->bo_entries);

	for (int i = 0; i < e->n_contexts; i++) {
		if (e->contexts[i])
			xfree(e->contexts[i]);
	}
	xfree(e->contexts);

	xfree(e);
}

int amdgpu_plugin_drm_handle_device_vma(int fd, const struct stat *st)
{
	char path[PATH_MAX];
	struct stat drm;
	int ret = 0;

	snprintf(path, sizeof(path), AMDGPU_DRM_DEVICE, DRM_FIRST_RENDER_NODE);
	ret = stat(path, &drm);
	if (ret) {
		pr_err("Error in getting stat for: %s\n", path);
		return -errno;
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
	size_t image_size = 0, buffer_size = 0;
	struct amdgpu_gpu_info gpu_info = {};
	amdgpu_device_handle h_dev;
	uint64_t max_copy_size;
	uint32_t major, minor;
	void *buffer = NULL;
	int bo_contents_fd;
	char img_path[40];
	int i, ret = 0;

	ret = amdgpu_device_initialize(drm_fd, &major, &minor, &h_dev);
	if (ret) {
		pr_err("failed to initialize device - %s\n", strerror(-ret));
		goto exit;
	}

	ret = amdgpu_query_gpu_info(h_dev, &gpu_info);
	if (ret) {
		pr_err("failed to query gpuinfo via libdrm - %s\n",
		       strerror(-ret));
		goto exit;
	}

	max_copy_size = (gpu_info.family_id >= AMDGPU_FAMILY_AI) ? SDMA_LINEAR_COPY_MAX_SIZE :
								   SDMA_LINEAR_COPY_MAX_SIZE - 1;

	for (i = 0; i < rd->num_of_bos; i++) {
		DrmBoEntry *entry = rd->bo_entries[i];

		if ((entry->preferred_domains &
		     (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)) &&
		    !entry->is_userptr) {
			if (entry->size > buffer_size)
				buffer_size = entry->size;
		}
	}

	if (!buffer_size)
		goto exit;

	ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (ret) {
		errno = ret;
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ret;
		goto exit;
	}

	for (i = 0; i < rd->num_of_bos; i++) {
		if (rd->bo_entries[i]->is_userptr)
			continue;

		if (!(rd->bo_entries[i]->preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GTT)))
			continue;

		if (rd->bo_entries[i]->num_of_vms == 0)
			continue;

		snprintf(img_path, sizeof(img_path), IMG_DRM_PAGES_FILE, rd->id, drm_render_minor, i);

		bo_contents_fd = open_img_file(img_path, false, &image_size, true);
		if (bo_contents_fd < 0) {
			ret = bo_contents_fd;
			break;
		}

		ret = sdma_copy_bo(dmabufs[i], rd->bo_entries[i]->size,
				   bo_contents_fd, buffer, buffer_size, h_dev,
				   max_copy_size, SDMA_OP_VRAM_WRITE, true);
		close(bo_contents_fd);
		if (ret) {
			pr_err("Failed to fill the BO using sDMA: bo_buckets[%d]\n", i);
			break;
		}
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
	struct drm_amdgpu_gem_list_handles_entry *entries = NULL;
	struct drm_amdgpu_gem_list_handles handles = {
		.num_entries = 8,
	};
	struct drm_amdgpu_gem_list_contexts_entry *contexts = NULL;
	struct drm_amdgpu_gem_list_contexts contexts_query = {
		.num_contexts = 8,
	};
	bool libdrm_initialized = false;
	unsigned long buffer_size = 0;
	amdgpu_device_handle h_dev;
	char path[PATH_MAX];
	CriuRenderNode *rd;
	unsigned char *buf;
	void *buffer = NULL;
	int len, ret;
	size_t image_size;
	struct tp_node *tp_node;

	rd = xmalloc(sizeof(*rd));
	if (!rd)
		return -ENOMEM;

	criu_render_node__init(rd);

	/* Get the topology node of the DRM device */
	rd->drm_render_minor = minor(drm->st_rdev);
	rd->id = id;

	do {
		unsigned int num_entries = handles.num_entries;

		if (entries) {
			xfree(entries);
			entries = NULL;
		}

		entries = xzalloc(sizeof(*entries) * handles.num_entries);
		if (!entries) {
			ret = -ENOMEM;
			goto exit;
		}

		handles.entries = (uintptr_t)entries;
		ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_LIST_HANDLES, &handles);
		if (ret) {
			ret = -errno;
			if (errno == EINVAL)
				pr_err("This kernel appears not to have AMDGPU_GEM_LIST_HANDLES ioctl. Consider disabling Dmabuf IPC or updating your kernel.\n");
			else
				pr_perror("Failed to call bo info ioctl");
			goto exit;
		}

		if (handles.num_entries <= num_entries)
			break;
	} while (true);

	do {
		unsigned int num_contexts = contexts_query.num_contexts;

		if (contexts) {
			xfree(contexts);
			contexts = NULL;
		}

		contexts = xzalloc(sizeof(*contexts) * contexts_query.num_contexts);
		if (!contexts) {
			ret = -ENOMEM;
			goto exit;
		}

		contexts_query.contexts = (uintptr_t)contexts;
		ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_LIST_CONTEXTS, &contexts_query);
		if (ret) {
			ret = -errno;
			if (errno == EINVAL) {
				pr_info("This kernel appears not to have AMDGPU_GEM_LIST_CONTEXTS ioctl. Consider updating your kernel.\n");
				contexts_query.num_contexts = 0;
				break;
			} else {
				pr_perror("Failed to call bo info ioctl");
				goto exit;
			}
		}

		if (contexts_query.num_contexts <= num_contexts)
			break;
	} while (true);

	rd->num_of_bos = handles.num_entries;
	ret = allocate_bo_entries(rd, handles.num_entries);
	if (ret)
		goto exit;

	if (contexts_query.num_contexts) {
		rd->num_of_contexts = contexts_query.num_contexts;
		ret = allocate_context_entries(rd, contexts_query.num_contexts);
		if (ret)
			goto exit;
		rd->has_num_of_contexts = true;
	}

	for (unsigned int i = 0; i < contexts_query.num_contexts; i++) {
		struct drm_amdgpu_gem_list_contexts_entry *entry = &contexts[i];
		DrmContextEntry *context = rd->contexts[i];

		context->handle = entry->handle;
		context->flags = entry->flags;
		context->init_priority = entry->init_priority;
		context->override_priority = entry->override_priority;
		context->pstate_flags = entry->pstate_flags;

		pr_info("Saving context %u/%u: %u %x %d/%d %x\n",
			i, contexts_query.num_contexts,
			context->handle, context->flags, context->init_priority,
			context->override_priority, context->pstate_flags);
	}

	for (int i = 0; i < handles.num_entries; i++) {
		int num_vm_entries = 8;
		struct drm_amdgpu_gem_vm_entry *vm_info_entries = NULL;
		DrmBoEntry *boinfo = rd->bo_entries[i];
		struct drm_amdgpu_gem_list_handles_entry *entry = &entries[i];
		int bo_contents_fd;
		int dmabuf_fd;

		boinfo->size = entry->size;
		boinfo->alloc_flags = entry->alloc_flags;
		boinfo->preferred_domains = entry->preferred_domains;
		boinfo->alignment = entry->alignment; /* Also sets userptr address. */
		boinfo->handle = entry->gem_handle;
		boinfo->is_import = (entry->flags & AMDGPU_GEM_LIST_HANDLES_FLAG_IS_IMPORT) || shared_bo_has_exporter(boinfo->handle);
		if (entry->flags & AMDGPU_GEM_LIST_HANDLES_FLAG_IS_USERPTR)
			boinfo->is_userptr = boinfo->has_is_userptr = true;

		if (!boinfo->is_userptr) {
			union drm_amdgpu_gem_mmap mmap_args = { 0 };

			mmap_args.in.handle = boinfo->handle;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_MMAP, &mmap_args) == -1) {
				pr_perror("Error Failed to call mmap ioctl");
				ret = -1;
				goto exit;
			}

			boinfo->offset = mmap_args.out.addr_ptr;
		}

		while (1) {
			struct drm_amdgpu_gem_op vm_info_args = {
				.handle = entry->gem_handle,
				.num_entries = num_vm_entries,
				.op = AMDGPU_GEM_OP_GET_MAPPING_INFO,
			};

			if (vm_info_entries)
				xfree(vm_info_entries);
			vm_info_entries = xzalloc(sizeof(*vm_info_entries) *
						  num_vm_entries);
			if (!vm_info_entries) {
				ret = -ENOMEM;
				goto exit;
			}

			vm_info_args.value = (uintptr_t)vm_info_entries;
			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_OP,
				       &vm_info_args);
			if (ret) {
				pr_perror("Failed to call vm info ioctl");
				xfree(vm_info_entries);
				goto exit;
			}

			if (vm_info_args.num_entries <= num_vm_entries) {
				num_vm_entries = vm_info_args.num_entries;
				break;
			} else {
				num_vm_entries = vm_info_args.num_entries;
			}
		}

		boinfo->num_of_vms = num_vm_entries;
		ret = allocate_vm_entries(boinfo, num_vm_entries);
		if (ret) {
			xfree(vm_info_entries);
			goto exit;
		}

		for (int j = 0; j < num_vm_entries; j++) {
			DrmVmEntry *vminfo = boinfo->vm_entries[j];

			boinfo->addr = vm_info_entries[j].addr;
			vminfo->addr = vm_info_entries[j].addr;
			vminfo->size = vm_info_entries[j].size;
			vminfo->offset = vm_info_entries[j].offset;
			vminfo->flags = vm_info_entries[j].flags;
		}
		xfree(vm_info_entries);

		if (!libdrm_initialized) {
			uint32_t major, minor;
			char *drm_path;
			int drm_fd;

			/* Re-open device to avoid VA conflicts in sdma_copy_bo. */
			drm_path = drmGetRenderDeviceNameFromFd(fd);
			drm_fd = open(drm_path, O_RDWR | O_CLOEXEC);
			if (drm_fd < 0) {
				ret = -errno;
				pr_perror("Failed to re-open %s", drm_path);
				goto exit;
			}

			ret = amdgpu_device_initialize(drm_fd, &major, &minor,
						       &h_dev);
			close(drm_fd);
			if (ret) {
				pr_err("Failed to initialize amdgpu device - %s\n",
				       strerror(-ret));
				goto exit;
			}

			libdrm_initialized = true;
		}

		if (!boinfo->is_userptr) {
			ret = drmPrimeHandleToFD(fd, boinfo->handle, 0, &dmabuf_fd);
			if (ret) {
				pr_perror("Failed to get dmabuf fd from handle");
				goto exit;
			}

			snprintf(path, sizeof(path), IMG_DRM_PAGES_FILE, rd->id, rd->drm_render_minor, i);
			image_size = entry->size;
			bo_contents_fd = open_img_file(path, true, &image_size, true);
			if (bo_contents_fd < 0) {
				ret = bo_contents_fd;
				close(dmabuf_fd);
				goto exit;
			}

			if (buffer_size < entry->size) {
				if (buffer_size) {
					free(buffer);
					buffer = NULL;
				}

				ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE),
						     entry->size);
				if (ret) {
					errno = ret;
					pr_perror("Failed to allocate userptr buffer");
					ret = -ret;
					close(bo_contents_fd);
					close(dmabuf_fd);
					goto exit;
				}

				buffer_size = entry->size;
			}

			ret = sdma_copy_bo(dmabuf_fd, entry->size,
					   bo_contents_fd, buffer, entry->size,
					   h_dev, 0x1000, SDMA_OP_VRAM_READ,
					   false);
			close(bo_contents_fd);
			if (ret)
				goto exit;
		}

		if (dmabuf_fd != KFD_INVALID_FD)
			close(dmabuf_fd);
	}

	for (int i = 0; i < handles.num_entries; i++) {
		DrmBoEntry *boinfo = rd->bo_entries[i];

		ret = record_shared_bo(boinfo->handle, boinfo->is_import);
		if (ret)
			goto exit;
	}

	tp_node = sys_get_node_by_render_minor(&src_topology, rd->drm_render_minor);
	if (!tp_node) {
		pr_err("Failed to find a device with minor number = %d\n",
		       rd->drm_render_minor);
		return -ENODEV;
	}

	/* Get the GPU_ID of the DRM device */
	if (checkpoint_maps.mapped_cnt)
		rd->gpu_id = maps_get_dest_gpu(&checkpoint_maps, tp_node->gpu_id);
	else
		rd->gpu_id = tp_node->gpu_id; /* Render node only */
	if (!rd->gpu_id) {
		pr_err("Failed to find valid gpu_id for the device = %d\n", tp_node->gpu_id);
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
	free(buffer);
	xfree(entries);
	xfree(contexts);
	free_e(rd);
	if (libdrm_initialized)
		amdgpu_device_deinitialize(h_dev);
	return ret;
}

int amdgpu_plugin_drm_restore_file(int fd, CriuRenderNode *rd)
{
	int ret = 0;
	bool retry_needed = false;
	bool bo_restore_called = false;
	int *dmabufs = xmalloc(sizeof(int) * rd->num_of_bos);
	if (!dmabufs)
		return -ENOMEM;
	memset(dmabufs, 0xff, sizeof(int) * rd->num_of_bos);

	for (unsigned int i = 0; i < rd->num_of_contexts; i++) {
		DrmContextEntry *context = rd->contexts[i];
		union drm_amdgpu_ctx args = {};

		args.in.op = AMDGPU_CTX_OP_ALLOC_CTX;
		args.in.priority = context->init_priority;
		ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CTX, &args);
		if (ret < 0) {
			ret = -errno;
			pr_perror("Failed to create context");
			goto exit;
		}

		if (args.out.alloc.ctx_id != context->handle) {
			uint32_t id = args.out.alloc.ctx_id;

			args.in.op = AMDGPU_CTX_OP_CHANGE_HANDLE;
			args.in.ctx_id = id;
			args.in.flags = context->handle;
			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CTX, &args);
			if (ret < 0) {
				ret = -errno;
				pr_perror("Failed to rename context");
				goto exit;
			}
		}

		if (context->override_priority != AMDGPU_CTX_PRIORITY_UNSET) {
			union drm_amdgpu_sched sched = {};

			sched.in.op = AMDGPU_SCHED_OP_CONTEXT_PRIORITY_OVERRIDE;
			sched.in.ctx_id = context->handle;
			sched.in.priority = context->override_priority;
			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_SCHED, &sched);
			if (ret < 0) {
				ret = -errno;
				pr_perror("Failed to override context priority");
				goto exit;
			}
		}

		if (context->pstate_flags != AMDGPU_CTX_STABLE_PSTATE_NONE) {
			union drm_amdgpu_ctx pstate = {};

			pstate.in.op = AMDGPU_CTX_OP_SET_STABLE_PSTATE;
			pstate.in.ctx_id = context->handle;
			pstate.in.flags = context->pstate_flags;
			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_CTX, &pstate);
			if (ret < 0) {
				ret = -errno;
				pr_perror("Failed to set context pstate");
				goto exit;
			}
		}

		pr_info("Restored context %u/%" PRIu64 ": %u %x %d/%d %x\n",
			i, rd->num_of_contexts,
			context->handle, context->flags, context->init_priority,
			context->override_priority, context->pstate_flags);
	}

	for (int i = 0; i < rd->num_of_bos; i++) {
		DrmBoEntry *boinfo = rd->bo_entries[i];
		int dmabuf_fd = -1;
		uint32_t handle;
		struct drm_gem_change_handle change_args = { 0 };
		int fd_id;

		if (work_already_completed(boinfo->handle, rd->drm_render_minor)) {
			continue;
		} else if (boinfo->handle != -1) {
			if (boinfo->is_import) {
				fd_id = amdgpu_id_for_handle(boinfo->handle);
				if (fd_id == -1) {
					retry_needed = true;
					continue;
				}
				dmabuf_fd = fdstore_get(fd_id);
			}
		}

		if (boinfo->is_import) {
			if (dmabuf_fd == -1) {
				retry_needed = true;
				continue;
			}
			ret = drmPrimeFDToHandle(fd, dmabuf_fd, &handle);
			if (ret) {
				pr_perror("Failed to get handle from dmabuf fd");
				close(dmabuf_fd);
				goto exit;
			}
		} else if (boinfo->is_userptr) {
			struct drm_amdgpu_gem_userptr userptr_args = {
				.size = boinfo->size,
				.addr = boinfo->alignment,
				.flags = boinfo->alloc_flags & ~AMDGPU_GEM_USERPTR_VALIDATE,
			};

			ret = drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_USERPTR,
				       &userptr_args);
			if (ret < 0) {
				ret = -errno;
				pr_perror("Failed to create userptr object");
				goto exit;
			}
			handle = userptr_args.handle;
		} else {
			union drm_amdgpu_gem_create create_args = {};

			create_args.in.bo_size = boinfo->size;
			create_args.in.alignment = boinfo->alignment;
			create_args.in.domains = boinfo->preferred_domains;
			create_args.in.domain_flags = boinfo->alloc_flags;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_CREATE, &create_args) == -1) {
				pr_perror("Error Failed to call create ioctl");
				ret = -1;
				goto exit;
			}
			handle = create_args.out.handle;

			ret = drmPrimeHandleToFD(fd, handle, 0, &dmabuf_fd);
			if (ret) {
				pr_perror("Failed to get dmabuf fd from handle");
				goto exit;
			}
		}

		change_args.handle = handle;
		change_args.new_handle = boinfo->handle;

		if (drmIoctl(fd, DRM_IOCTL_GEM_CHANGE_HANDLE, &change_args) == -1) {
			pr_perror("Error Failed to call change ioctl; check if the kernel has DRM_IOCTL_GEM_CHANGE_HANDLE support");
			ret = -1;
			goto exit;
		}

		if (!boinfo->is_import)
			store_dmabuf_fd(boinfo->handle, dmabuf_fd);

		dmabufs[i] = dmabuf_fd;

		ret = record_completed_work(boinfo->handle, rd->drm_render_minor);
		if (ret)
			goto exit;

		if (!boinfo->is_userptr) {
			union drm_amdgpu_gem_mmap mmap_args = {};

			mmap_args.in.handle = boinfo->handle;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_MMAP, &mmap_args) == -1) {
				pr_perror("Error Failed to call mmap ioctl");
				ret = -1;
				goto exit;
			}

			ret = save_vma_updates(boinfo->offset, boinfo->addr,
					       mmap_args.out.addr_ptr, fd);
			if (ret < 0)
				goto exit;
		}
	}

	if (ret) {
		pr_info("Error in deinit amdgpu device\n");
		goto exit;
	}

	if (retry_needed)
		goto exit;

	ret = record_completed_work(-1, rd->drm_render_minor);
	if (ret)
		goto exit;

	if (rd->num_of_bos > 0) {
		bo_restore_called = true;
		ret = restore_bo_contents_drm(rd->drm_render_minor, rd, fd, dmabufs);
		if (ret)
			goto exit;
	}

	for (int i = 0; i < rd->num_of_bos; i++) {
		DrmBoEntry *boinfo = rd->bo_entries[i];

		for (int j = 0; j < boinfo->num_of_vms; j++) {
			DrmVmEntry *vminfo = boinfo->vm_entries[j];
			struct drm_amdgpu_gem_va va_args = { };

			va_args.handle = boinfo->handle;
			va_args.operation = AMDGPU_VA_OP_MAP;
			va_args.flags = vminfo->flags;
			va_args.va_address = vminfo->addr;
			va_args.offset_in_bo = vminfo->offset;
			va_args.map_size = vminfo->size;

			if (drmIoctl(fd, DRM_IOCTL_AMDGPU_GEM_VA, &va_args) == -1) {
				ret = -errno;
				pr_perror("Failed to map bo %u/%u!", i, j);
				goto exit;
			}
		}
	}

exit:
	if (ret < 0 && !bo_restore_called) {
		for (int i = 0; i < rd->num_of_bos; i++) {
			if (dmabufs[i] != KFD_INVALID_FD)
				close(dmabufs[i]);
		}
	}
	xfree(dmabufs);

	if (ret < 0)
		return ret;

	return retry_needed;
}
