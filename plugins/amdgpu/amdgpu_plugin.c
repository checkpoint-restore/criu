#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>

#include <xf86drm.h>
#include <libdrm/amdgpu.h>
#include <libdrm/amdgpu_drm.h>

#include "criu-plugin.h"
#include "plugin.h"
#include "criu-amdgpu.pb-c.h"

#include "kfd_ioctl.h"
#include "xmalloc.h"
#include "criu-log.h"
#include "files.h"
#include "pstree.h"

#include "common/list.h"
#include "amdgpu_plugin_drm.h"
#include "amdgpu_plugin_util.h"
#include "amdgpu_plugin_topology.h"
#include "amdgpu_socket_utils.h"

#include "img-streamer.h"
#include "image.h"
#include "cr_options.h"

struct vma_metadata {
	struct list_head list;
	uint64_t old_pgoff;
	uint64_t new_pgoff;
	uint64_t vma_entry;
	uint32_t new_minor;
	int fd;
};

/************************************ Global Variables ********************************************/

/**
 * FD of KFD device used to checkpoint. On a multi-process
 * tree the order of checkpointing goes from parent to child
 * and so on - so saving the FD will not be overwritten
 */
static int kfd_checkpoint_fd;

static LIST_HEAD(update_vma_info_list);

size_t kfd_max_buffer_size;

bool plugin_added_to_inventory = false;

bool plugin_disabled = false;

/*
 * In the case of a single process (common case), this optimization can effectively
 * reduce the restore latency with parallel restore. In the case of multiple processes,
 * states are already restored in parallel within different processes. Therefore, this
 * optimization does not introduce further improvement and will be disabled by default
 * in this case. The flag, parallel_disabled, is used to control whether the
 * optimization is enabled or disabled.
 */
bool parallel_disabled = false;

pthread_t parallel_thread = 0;
int parallel_thread_result = 0;
/**************************************************************************************************/

/* Call ioctl, restarting if it is interrupted */
int kmtIoctl(int fd, unsigned long request, void *arg)
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

static void free_e(CriuKfd *e)
{
	for (int i = 0; i < e->n_bo_entries; i++) {
		if (e->bo_entries[i])
			xfree(e->bo_entries[i]);
	}

	for (int i = 0; i < e->n_device_entries; i++) {
		if (e->device_entries[i]) {
			for (int j = 0; j < e->device_entries[i]->n_iolinks; j++)
				xfree(e->device_entries[i]->iolinks[j]);

			xfree(e->device_entries[i]);
		}
	}
	xfree(e);
}

static int allocate_device_entries(CriuKfd *e, int num_of_devices)
{
	e->device_entries = xmalloc(sizeof(KfdDeviceEntry *) * num_of_devices);
	if (!e->device_entries) {
		pr_err("Failed to allocate device_entries\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_of_devices; i++) {
		KfdDeviceEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate entry\n");
			return -ENOMEM;
		}

		kfd_device_entry__init(entry);

		e->device_entries[i] = entry;
		e->n_device_entries++;
	}
	return 0;
}

static int allocate_bo_entries(CriuKfd *e, int num_bos, struct kfd_criu_bo_bucket *bo_bucket_ptr)
{
	e->bo_entries = xmalloc(sizeof(KfdBoEntry *) * num_bos);
	if (!e->bo_entries) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_bos; i++) {
		KfdBoEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		kfd_bo_entry__init(entry);

		e->bo_entries[i] = entry;
		e->n_bo_entries++;
	}
	return 0;
}

int topology_to_devinfo(struct tp_system *sys, struct device_maps *maps, KfdDeviceEntry **deviceEntries)
{
	uint32_t devinfo_index = 0;
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		KfdDeviceEntry *devinfo = deviceEntries[devinfo_index++];

		devinfo->node_id = node->id;

		if (NODE_IS_GPU(node)) {
			devinfo->gpu_id = maps_get_dest_gpu(maps, node->gpu_id);
			if (!devinfo->gpu_id)
				return -EINVAL;

			devinfo->simd_count = node->simd_count;
			devinfo->mem_banks_count = node->mem_banks_count;
			devinfo->caches_count = node->caches_count;
			devinfo->io_links_count = node->io_links_count;
			devinfo->max_waves_per_simd = node->max_waves_per_simd;
			devinfo->lds_size_in_kb = node->lds_size_in_kb;
			devinfo->num_gws = node->num_gws;
			devinfo->wave_front_size = node->wave_front_size;
			devinfo->array_count = node->array_count;
			devinfo->simd_arrays_per_engine = node->simd_arrays_per_engine;
			devinfo->cu_per_simd_array = node->cu_per_simd_array;
			devinfo->simd_per_cu = node->simd_per_cu;
			devinfo->max_slots_scratch_cu = node->max_slots_scratch_cu;
			devinfo->vendor_id = node->vendor_id;
			devinfo->device_id = node->device_id;
			devinfo->domain = node->domain;
			devinfo->drm_render_minor = node->drm_render_minor;
			devinfo->hive_id = node->hive_id;
			devinfo->num_sdma_engines = node->num_sdma_engines;
			devinfo->num_sdma_xgmi_engines = node->num_sdma_xgmi_engines;
			devinfo->num_sdma_queues_per_engine = node->num_sdma_queues_per_engine;
			devinfo->num_cp_queues = node->num_cp_queues;
			devinfo->fw_version = node->fw_version;
			devinfo->capability = node->capability;
			devinfo->sdma_fw_version = node->sdma_fw_version;
			devinfo->vram_public = node->vram_public;
			devinfo->vram_size = node->vram_size;
		} else {
			devinfo->cpu_cores_count = node->cpu_cores_count;
		}

		if (node->num_valid_iolinks) {
			struct tp_iolink *iolink;
			uint32_t iolink_index = 0;

			devinfo->iolinks = xmalloc(sizeof(DevIolink *) * node->num_valid_iolinks);
			if (!devinfo->iolinks)
				return -ENOMEM;

			list_for_each_entry(iolink, &node->iolinks, listm) {
				if (!iolink->valid)
					continue;

				devinfo->iolinks[iolink_index] = xmalloc(sizeof(DevIolink));
				if (!devinfo->iolinks[iolink_index])
					return -ENOMEM;

				dev_iolink__init(devinfo->iolinks[iolink_index]);

				devinfo->iolinks[iolink_index]->type = iolink->type;
				devinfo->iolinks[iolink_index]->node_to_id = iolink->node_to_id;
				iolink_index++;
			}
			devinfo->n_iolinks = iolink_index;
		}
	}
	return 0;
}

int devinfo_to_topology(KfdDeviceEntry *devinfos[], uint32_t num_devices, struct tp_system *sys)
{
	for (int i = 0; i < num_devices; i++) {
		struct tp_node *node;
		KfdDeviceEntry *devinfo = devinfos[i];

		node = sys_add_node(sys, devinfo->node_id, devinfo->gpu_id);
		if (!node)
			return -ENOMEM;

		if (devinfo->cpu_cores_count) {
			node->cpu_cores_count = devinfo->cpu_cores_count;
		} else {
			node->simd_count = devinfo->simd_count;
			node->mem_banks_count = devinfo->mem_banks_count;
			node->caches_count = devinfo->caches_count;
			node->io_links_count = devinfo->io_links_count;
			node->max_waves_per_simd = devinfo->max_waves_per_simd;
			node->lds_size_in_kb = devinfo->lds_size_in_kb;
			node->num_gws = devinfo->num_gws;
			node->wave_front_size = devinfo->wave_front_size;
			node->array_count = devinfo->array_count;
			node->simd_arrays_per_engine = devinfo->simd_arrays_per_engine;
			node->cu_per_simd_array = devinfo->cu_per_simd_array;
			node->simd_per_cu = devinfo->simd_per_cu;
			node->max_slots_scratch_cu = devinfo->max_slots_scratch_cu;
			node->vendor_id = devinfo->vendor_id;
			node->device_id = devinfo->device_id;
			node->domain = devinfo->domain;
			node->drm_render_minor = devinfo->drm_render_minor;
			node->hive_id = devinfo->hive_id;
			node->num_sdma_engines = devinfo->num_sdma_engines;
			node->num_sdma_xgmi_engines = devinfo->num_sdma_xgmi_engines;
			node->num_sdma_queues_per_engine = devinfo->num_sdma_queues_per_engine;
			node->num_cp_queues = devinfo->num_cp_queues;
			node->fw_version = devinfo->fw_version;
			node->capability = devinfo->capability;
			node->sdma_fw_version = devinfo->sdma_fw_version;
			node->vram_public = devinfo->vram_public;
			node->vram_size = devinfo->vram_size;
		}

		for (int j = 0; j < devinfo->n_iolinks; j++) {
			struct tp_iolink *iolink;
			DevIolink *devlink = (devinfo->iolinks[j]);

			iolink = node_add_iolink(node, devlink->type, devlink->node_to_id);
			if (!iolink)
				return -ENOMEM;
		}
	}
	return 0;
}

void getenv_bool(const char *var, bool *value)
{
	char *value_str = getenv(var);

	if (value_str) {
		if (!strcmp(value_str, "0") || !strcasecmp(value_str, "NO"))
			*value = false;
		else if (!strcmp(value_str, "1") || !strcasecmp(value_str, "YES"))
			*value = true;
		else
			pr_err("Ignoring invalid value for %s=%s, expecting (YES/NO)\n", var, value_str);
	}
	pr_info("param: %s:%s\n", var, *value ? "Y" : "N");
}

void getenv_size_t(const char *var, size_t *value)
{
	char *value_str = getenv(var);
	char *endp = value_str;
	int sh = 0;
	size_t size;

	pr_info("Value str: %s\n", value_str);

	if (value_str) {
		size = (size_t)strtoul(value_str, &endp, 0);
		if (errno || value_str == endp) {
			pr_err("Ignoring invalid value for %s=%s, expecting a positive integer\n", var, value_str);
			return;
		}
		switch (*endp) {
		case 'k':
		case 'K':
			sh = 10;
			break;
		case 'M':
			sh = 20;
			break;
		case 'G':
			sh = 30;
			break;
		case '\0':
			sh = 0;
			break;
		default:
			pr_err("Ignoring invalid size suffix for %s=%s, expecting 'K'/k', 'M', or 'G'\n", var, value_str);
			return;
		}
		if (SIZE_MAX >> sh < size) {
			pr_err("Ignoring invalid value for %s=%s, exceeds SIZE_MAX\n", var, value_str);
			return;
		}
		*value = size << sh;
	}
	pr_info("param: %s:0x%lx\n", var, *value);
}

int amdgpu_plugin_init(int stage)
{
	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (!check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name, strlen(CR_PLUGIN_DESC.name))) {
			plugin_disabled = true;
			return 0;
		}
	}

	pr_info("initialized:  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);

	topology_init(&src_topology);
	topology_init(&dest_topology);
	maps_init(&checkpoint_maps);
	maps_init(&restore_maps);

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (has_children(root_item)) {
			pr_info("Parallel restore disabled\n");
			parallel_disabled = true;
		} else {
			if (install_parallel_sock() < 0) {
				pr_err("Failed to install parallel socket\n");
				return -1;
			}
		}
		/* Default Values */
		kfd_fw_version_check = true;
		kfd_sdma_fw_version_check = true;
		kfd_caches_count_check = true;
		kfd_num_gws_check = true;
		kfd_vram_size_check = true;
		kfd_numa_check = true;
		kfd_capability_check = true;

		getenv_bool("KFD_FW_VER_CHECK", &kfd_fw_version_check);
		getenv_bool("KFD_SDMA_FW_VER_CHECK", &kfd_sdma_fw_version_check);
		getenv_bool("KFD_CACHES_COUNT_CHECK", &kfd_caches_count_check);
		getenv_bool("KFD_NUM_GWS_CHECK", &kfd_num_gws_check);
		getenv_bool("KFD_VRAM_SIZE_CHECK", &kfd_vram_size_check);
		getenv_bool("KFD_NUMA_CHECK", &kfd_numa_check);
		getenv_bool("KFD_CAPABILITY_CHECK", &kfd_capability_check);
	}
	kfd_max_buffer_size = 0;
	getenv_size_t("KFD_MAX_BUFFER_SIZE", &kfd_max_buffer_size);

	return 0;
}

void amdgpu_plugin_fini(int stage, int ret)
{
	if (plugin_disabled)
		return;

	pr_info("finished  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);

	if (stage == CR_PLUGIN_STAGE__RESTORE)
		sys_close_drm_render_devices(&dest_topology);

	maps_free(&checkpoint_maps);
	maps_free(&restore_maps);

	topology_free(&src_topology);
	topology_free(&dest_topology);
}

CR_PLUGIN_REGISTER("amdgpu_plugin", amdgpu_plugin_init, amdgpu_plugin_fini)

struct thread_data {
	pthread_t thread;
	uint64_t num_of_bos;
	uint32_t gpu_id;
	pid_t pid;
	struct kfd_criu_bo_bucket *bo_buckets;
	KfdBoEntry **bo_entries;
	int drm_fd;
	int ret;
	int id; /* File ID used by CRIU to identify KFD image for this process */
};

int amdgpu_plugin_handle_device_vma(int fd, const struct stat *st_buf)
{
	struct stat st_kfd;
	int ret = 0;

	pr_debug("Enter %s\n", __func__);
	ret = stat(AMDGPU_KFD_DEVICE, &st_kfd);
	if (ret == -1) {
		pr_perror("stat error for /dev/kfd");
		return ret;
	}

	/* If input device is KFD return device as supported */
	if (major(st_buf->st_rdev) == major(st_kfd.st_rdev)) {
		pr_debug("Known non-regular mapping, kfd-renderD%d -> OK\n", minor(st_buf->st_rdev));
		return 0;
	}

	/* Determine if input is a DRM device and therefore is supported */
	ret = amdgpu_plugin_drm_handle_device_vma(fd, st_buf);
	if (ret)
		pr_perror("%s(), Can't handle VMAs of input device", __func__);

	if (!ret && !plugin_added_to_inventory) {
		ret = add_inventory_plugin(CR_PLUGIN_DESC.name);
		if (ret)
			pr_err("Failed to add AMDGPU plugin to inventory image\n");
		else
			plugin_added_to_inventory = true;
	}

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, amdgpu_plugin_handle_device_vma)

int alloc_and_map(amdgpu_device_handle h_dev, uint64_t size, uint32_t domain, amdgpu_bo_handle *ph_bo,
		  amdgpu_va_handle *ph_va, uint64_t *p_gpu_addr, void **p_cpu_addr)
{
	struct amdgpu_bo_alloc_request alloc_req;
	amdgpu_bo_handle h_bo;
	amdgpu_va_handle h_va;
	uint64_t gpu_addr;
	void *cpu_addr;
	int err;

	memset(&alloc_req, 0, sizeof(alloc_req));
	alloc_req.alloc_size = size;
	alloc_req.phys_alignment = 0x1000;
	alloc_req.preferred_heap = domain;
	alloc_req.flags = 0;
	err = amdgpu_bo_alloc(h_dev, &alloc_req, &h_bo);
	if (err) {
		pr_perror("failed to alloc BO");
		return err;
	}
	err = amdgpu_va_range_alloc(h_dev, amdgpu_gpu_va_range_general, size, 0x1000, 0, &gpu_addr, &h_va, 0);
	if (err) {
		pr_perror("failed to alloc VA");
		goto err_va;
	}
	err = amdgpu_bo_va_op(h_bo, 0, size, gpu_addr, 0, AMDGPU_VA_OP_MAP);
	if (err) {
		pr_perror("failed to GPU map BO");
		goto err_gpu_map;
	}
	if (p_cpu_addr) {
		err = amdgpu_bo_cpu_map(h_bo, &cpu_addr);
		if (err) {
			pr_perror("failed to CPU map BO");
			goto err_cpu_map;
		}
		*p_cpu_addr = cpu_addr;
	}

	*ph_bo = h_bo;
	*ph_va = h_va;
	*p_gpu_addr = gpu_addr;

	return 0;

err_cpu_map:
	amdgpu_bo_va_op(h_bo, 0, size, gpu_addr, 0, AMDGPU_VA_OP_UNMAP);
err_gpu_map:
	amdgpu_va_range_free(h_va);
err_va:
	amdgpu_bo_free(h_bo);
	return err;
}

void free_and_unmap(uint64_t size, amdgpu_bo_handle h_bo, amdgpu_va_handle h_va, uint64_t gpu_addr, void *cpu_addr)
{
	if (cpu_addr)
		amdgpu_bo_cpu_unmap(h_bo);
	amdgpu_bo_va_op(h_bo, 0, size, gpu_addr, 0, AMDGPU_VA_OP_UNMAP);
	amdgpu_va_range_free(h_va);
	amdgpu_bo_free(h_bo);
}

static int sdma_copy_bo(struct kfd_criu_bo_bucket bo_bucket, FILE *storage_fp,
						void *buffer, size_t buffer_size, amdgpu_device_handle h_dev,
						uint64_t max_copy_size, enum sdma_op_type type)
{
	uint64_t size, src_bo_size, dst_bo_size, buffer_bo_size, bytes_remain, buffer_space_remain;
	uint64_t gpu_addr_src, gpu_addr_dst, gpu_addr_ib, copy_src, copy_dst, copy_size;
	amdgpu_va_handle h_va_src, h_va_dst, h_va_ib;
	amdgpu_bo_handle h_bo_src, h_bo_dst, h_bo_ib;
	struct amdgpu_bo_import_result res = { 0 };
	struct amdgpu_cs_ib_info ib_info;
	amdgpu_bo_list_handle h_bo_list;
	struct amdgpu_cs_request cs_req;
	amdgpu_bo_handle resources[3];
	struct amdgpu_cs_fence fence;
	uint32_t expired;
	amdgpu_context_handle h_ctx;
	uint32_t *ib = NULL;
	int j, err, shared_fd, packets_per_buffer;

	shared_fd = bo_bucket.dmabuf_fd;
	size = bo_bucket.size;
	buffer_bo_size = min(size, buffer_size);
	packets_per_buffer = ((buffer_bo_size - 1) / max_copy_size) + 1;
	src_bo_size = (type == SDMA_OP_VRAM_WRITE) ? buffer_bo_size : size;
	dst_bo_size = (type == SDMA_OP_VRAM_READ) ? buffer_bo_size : size;

	plugin_log_msg("Enter %s\n", __func__);

	/* prepare src buffer */
	switch (type) {
	case SDMA_OP_VRAM_WRITE:
		err = amdgpu_create_bo_from_user_mem(h_dev, buffer, src_bo_size, &h_bo_src);
		if (err) {
			pr_perror("failed to create userptr for sdma");
			return -EFAULT;
		}
		break;
	case SDMA_OP_VRAM_READ:
		err = amdgpu_bo_import(h_dev, amdgpu_bo_handle_type_dma_buf_fd, shared_fd, &res);
		if (err) {
			pr_perror("failed to import dmabuf handle from libdrm");
			return -EFAULT;
		}
		h_bo_src = res.buf_handle;
		break;
	default:
		pr_perror("Invalid sdma operation");
		return -EINVAL;
	}

	err = amdgpu_va_range_alloc(h_dev, amdgpu_gpu_va_range_general, src_bo_size, 0x1000, 0, &gpu_addr_src,
				    &h_va_src, 0);
	if (err) {
		pr_perror("failed to alloc VA for src bo");
		goto err_src_va;
	}
	err = amdgpu_bo_va_op(h_bo_src, 0, src_bo_size, gpu_addr_src, 0, AMDGPU_VA_OP_MAP);
	if (err) {
		pr_perror("failed to GPU map the src BO");
		goto err_src_bo_map;
	}
	plugin_log_msg("Source BO: GPU VA: %lx, size: %lx\n", gpu_addr_src, src_bo_size);

	/* prepare dest buffer */
	switch (type) {
	case SDMA_OP_VRAM_WRITE:
		err = amdgpu_bo_import(h_dev, amdgpu_bo_handle_type_dma_buf_fd, shared_fd, &res);
		if (err) {
			pr_perror("failed to import dmabuf handle from libdrm");
			goto err_dst_bo_prep;
		}
		h_bo_dst = res.buf_handle;
		break;
	case SDMA_OP_VRAM_READ:
		err = amdgpu_create_bo_from_user_mem(h_dev, buffer, dst_bo_size, &h_bo_dst);
		if (err) {
			pr_perror("failed to create userptr for sdma");
			goto err_dst_bo_prep;
		}
		break;
	default:
		pr_perror("Invalid sdma operation");
		goto err_dst_bo_prep;
	}

	err = amdgpu_va_range_alloc(h_dev, amdgpu_gpu_va_range_general, dst_bo_size, 0x1000, 0, &gpu_addr_dst,
				    &h_va_dst, 0);
	if (err) {
		pr_perror("failed to alloc VA for dest bo");
		goto err_dst_va;
	}
	err = amdgpu_bo_va_op(h_bo_dst, 0, dst_bo_size, gpu_addr_dst, 0, AMDGPU_VA_OP_MAP);
	if (err) {
		pr_perror("failed to GPU map the dest BO");
		goto err_dst_bo_map;
	}
	plugin_log_msg("Dest BO: GPU VA: %lx, size: %lx\n", gpu_addr_dst, dst_bo_size);

	/* prepare ring buffer/indirect buffer for command submission
	 * each copy packet is 7 dwords so we need to alloc 28x size for ib
	 */
	err = alloc_and_map(h_dev, packets_per_buffer * 28, AMDGPU_GEM_DOMAIN_GTT, &h_bo_ib, &h_va_ib, &gpu_addr_ib,
			    (void **)&ib);
	if (err) {
		pr_perror("failed to allocate and map ib/rb");
		goto err_ib_gpu_alloc;
	}
	plugin_log_msg("Indirect BO: GPU VA: %lx, size: %lx\n", gpu_addr_ib, packets_per_buffer * 28);

	resources[0] = h_bo_src;
	resources[1] = h_bo_dst;
	resources[2] = h_bo_ib;
	err = amdgpu_bo_list_create(h_dev, 3, resources, NULL, &h_bo_list);
	if (err) {
		pr_perror("failed to create BO resources list");
		goto err_bo_list;
	}

	bytes_remain = size;
	if (type == SDMA_OP_VRAM_WRITE)
		copy_dst = gpu_addr_dst;
	else
		copy_src = gpu_addr_src;

	while (bytes_remain > 0) {
		memset(&cs_req, 0, sizeof(cs_req));
		memset(&fence, 0, sizeof(fence));
		memset(&ib_info, 0, sizeof(ib_info));
		memset(ib, 0, packets_per_buffer * 28);

		if (type == SDMA_OP_VRAM_WRITE) {
			err = read_fp(storage_fp, buffer, min(bytes_remain, buffer_bo_size));
			if (err) {
				pr_perror("failed to read from storage");
				goto err_bo_list;
			}
		}

		buffer_space_remain = buffer_bo_size;
		if (type == SDMA_OP_VRAM_WRITE)
			copy_src = gpu_addr_src;
		else
			copy_dst = gpu_addr_dst;
		j = 0;

		while (bytes_remain > 0 && buffer_space_remain > 0) {
			copy_size = min(min(bytes_remain, max_copy_size), buffer_space_remain);

			ib[j++] = SDMA_PACKET(SDMA_OPCODE_COPY, SDMA_COPY_SUB_OPCODE_LINEAR, 0);
			ib[j++] = copy_size;
			ib[j++] = 0;
			ib[j++] = 0xffffffff & copy_src;
			ib[j++] = (0xffffffff00000000 & copy_src) >> 32;
			ib[j++] = 0xffffffff & copy_dst;
			ib[j++] = (0xffffffff00000000 & copy_dst) >> 32;

			copy_src += copy_size;
			copy_dst += copy_size;
			bytes_remain -= copy_size;
			buffer_space_remain -= copy_size;
		}
		/* pad the IB to the required number of dw with SDMA_NOP */
		while (j & 7)
			ib[j++] = SDMA_NOP;

		ib_info.ib_mc_address = gpu_addr_ib;
		ib_info.size = j;

		cs_req.ip_type = AMDGPU_HW_IP_DMA;
		/* possible future optimization: may use other rings, info available in
		 * amdgpu_query_hw_ip_info()
		 */
		cs_req.ring = 0;
		cs_req.number_of_ibs = 1;
		cs_req.ibs = &ib_info;
		cs_req.resources = h_bo_list;
		cs_req.fence_info.handle = NULL;

		err = amdgpu_cs_ctx_create(h_dev, &h_ctx);
		if (err) {
			pr_perror("failed to create context for SDMA command submission");
			goto err_ctx;
		}
		err = amdgpu_cs_submit(h_ctx, 0, &cs_req, 1);
		if (err) {
			pr_perror("failed to submit command for SDMA IB");
			goto err_cs_submit_ib;
		}

		fence.context = h_ctx;
		fence.ip_type = AMDGPU_HW_IP_DMA;
		fence.ip_instance = 0;
		fence.ring = 0;
		fence.fence = cs_req.seq_no;
		err = amdgpu_cs_query_fence_status(&fence, AMDGPU_TIMEOUT_INFINITE, 0, &expired);
		if (err) {
			pr_perror("failed to query fence status");
			goto err_cs_submit_ib;
		}
		if (!expired) {
			pr_err("IB execution did not complete\n");
			err = -EBUSY;
			goto err_cs_submit_ib;
		}

		if (type == SDMA_OP_VRAM_READ) {
			err = write_fp(storage_fp, buffer, buffer_bo_size - buffer_space_remain);
			if (err) {
				pr_perror("failed to write out to storage");
				goto err_cs_submit_ib;
			}
		}

err_cs_submit_ib:
		amdgpu_cs_ctx_free(h_ctx);
		if (err)
			break;
	}
err_ctx:
	amdgpu_bo_list_destroy(h_bo_list);
err_bo_list:
	free_and_unmap(packets_per_buffer * 28, h_bo_ib, h_va_ib, gpu_addr_ib, ib);
err_ib_gpu_alloc:
	err = amdgpu_bo_va_op(h_bo_dst, 0, size, gpu_addr_dst, 0, AMDGPU_VA_OP_UNMAP);
	if (err)
		pr_perror("failed to GPU unmap the dest BO %lx, size = %lx", gpu_addr_dst, size);
err_dst_bo_map:
	err = amdgpu_va_range_free(h_va_dst);
	if (err)
		pr_perror("dest range free failed");
err_dst_va:
	err = amdgpu_bo_free(h_bo_dst);
	if (err)
		pr_perror("dest bo free failed");
err_dst_bo_prep:
	err = amdgpu_bo_va_op(h_bo_src, 0, size, gpu_addr_src, 0, AMDGPU_VA_OP_UNMAP);
	if (err)
		pr_perror("failed to GPU unmap the src BO %lx, size = %lx", gpu_addr_src, size);
err_src_bo_map:
	err = amdgpu_va_range_free(h_va_src);
	if (err)
		pr_perror("src range free failed");
err_src_va:
	err = amdgpu_bo_free(h_bo_src);
	if (err)
		pr_perror("src bo free failed");
	plugin_log_msg("Leaving sdma_copy_bo, err = %d\n", err);
	return err;
}

void *dump_bo_contents(void *_thread_data)
{
	struct thread_data *thread_data = (struct thread_data *)_thread_data;
	struct kfd_criu_bo_bucket *bo_buckets = thread_data->bo_buckets;
	struct amdgpu_gpu_info gpu_info = { 0 };
	amdgpu_device_handle h_dev;
	size_t max_bo_size = 0, image_size = 0, buffer_size;
	uint64_t max_copy_size;
	uint32_t major, minor;
	int num_bos = 0;
	int i, ret = 0;
	FILE *bo_contents_fp = NULL;
	void *buffer = NULL;
	char img_path[40];

	pr_info("Thread[0x%x] started\n", thread_data->gpu_id);

	ret = amdgpu_device_initialize(thread_data->drm_fd, &major, &minor, &h_dev);
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

	for (i = 0; i < thread_data->num_of_bos; i++) {
		if (bo_buckets[i].gpu_id == thread_data->gpu_id &&
		    (bo_buckets[i].alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT))) {
			image_size += bo_buckets[i].size;
			if (bo_buckets[i].size > max_bo_size)
				max_bo_size = bo_buckets[i].size;
		}
	}

	buffer_size = kfd_max_buffer_size > 0 ? min(kfd_max_buffer_size, max_bo_size) : max_bo_size;

	posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (!buffer) {
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ENOMEM;
		goto exit;
	}

	snprintf(img_path, sizeof(img_path), IMG_KFD_PAGES_FILE, thread_data->id, thread_data->gpu_id);
	bo_contents_fp = open_img_file(img_path, true, &image_size);
	if (!bo_contents_fp) {
		pr_perror("Cannot fopen %s", img_path);
		ret = -EIO;
		goto exit;
	}

	for (i = 0; i < thread_data->num_of_bos; i++) {
		if (bo_buckets[i].gpu_id != thread_data->gpu_id)
			continue;

		if (!(bo_buckets[i].alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)))
			continue;

		num_bos++;

		/* perform sDMA based vram copy */
		ret = sdma_copy_bo(bo_buckets[i], bo_contents_fp, buffer, buffer_size, h_dev, max_copy_size,
				   SDMA_OP_VRAM_READ);
		if (ret) {
			pr_err("Failed to drain the BO using sDMA: bo_buckets[%d]\n", i);
			break;
		}
	}

exit:
	pr_info("Thread[0x%x] done num_bos:%d ret:%d\n", thread_data->gpu_id, num_bos, ret);

	if (bo_contents_fp)
		fclose(bo_contents_fp);

	xfree(buffer);

	amdgpu_device_deinitialize(h_dev);

	thread_data->ret = ret;
	return NULL;
};

void *restore_bo_contents(void *_thread_data)
{
	struct thread_data *thread_data = (struct thread_data *)_thread_data;
	struct kfd_criu_bo_bucket *bo_buckets = thread_data->bo_buckets;
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

	pr_info("Thread[0x%x] started\n", thread_data->gpu_id);

	ret = amdgpu_device_initialize(thread_data->drm_fd, &major, &minor, &h_dev);
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

	snprintf(img_path, sizeof(img_path), IMG_KFD_PAGES_FILE, thread_data->id, thread_data->gpu_id);
	bo_contents_fp = open_img_file(img_path, false, &image_size);
	if (!bo_contents_fp) {
		pr_perror("Cannot fopen %s", img_path);
		ret = -errno;
		goto exit;
	}

	for (i = 0; i < thread_data->num_of_bos; i++) {
		if (bo_buckets[i].gpu_id == thread_data->gpu_id &&
		    (bo_buckets[i].alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT))) {
			total_bo_size += bo_buckets[i].size;

			if (bo_buckets[i].size > max_bo_size)
				max_bo_size = bo_buckets[i].size;
		}
	}

	if (total_bo_size != image_size) {
		pr_err("%s size mismatch (current:%ld:expected:%ld)\n", img_path, image_size, total_bo_size);

		ret = -EINVAL;
		goto exit;
	}

	buffer_size = kfd_max_buffer_size > 0 ? min(kfd_max_buffer_size, max_bo_size) : max_bo_size;

	posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (!buffer) {
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < thread_data->num_of_bos; i++) {
		if (bo_buckets[i].gpu_id != thread_data->gpu_id)
			continue;

		if (!(bo_buckets[i].alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)))
			continue;

		num_bos++;

		ret = sdma_copy_bo(bo_buckets[i], bo_contents_fp, buffer, buffer_size, h_dev, max_copy_size,
				   SDMA_OP_VRAM_WRITE);
		if (ret) {
			pr_err("Failed to fill the BO using sDMA: bo_buckets[%d]\n", i);
			break;
		}
		plugin_log_msg("** Successfully filled the BO using sDMA: bo_buckets[%d] **\n", i);
	}

exit:
	pr_info("Thread[0x%x] done num_bos:%d ret:%d\n", thread_data->gpu_id, num_bos, ret);

	if (bo_contents_fp)
		fclose(bo_contents_fp);

	xfree(buffer);

	amdgpu_device_deinitialize(h_dev);
	thread_data->ret = ret;
	return NULL;
};

int check_hsakmt_shared_mem(uint64_t *shared_mem_size, uint32_t *shared_mem_magic)
{
	int ret;
	struct stat st;

	ret = stat(HSAKMT_SHM_PATH, &st);
	if (ret) {
		*shared_mem_size = 0;
		return 0;
	}

	*shared_mem_size = st.st_size;

	/* First 4 bytes of shared file is the magic */
	ret = read_file(HSAKMT_SHM_PATH, shared_mem_magic, sizeof(*shared_mem_magic));
	if (ret)
		pr_perror("Failed to read shared mem magic");
	else
		plugin_log_msg("Shared mem magic:0x%x\n", *shared_mem_magic);

	return 0;
}

int restore_hsakmt_shared_mem(const uint64_t shared_mem_size, const uint32_t shared_mem_magic)
{
	int ret, fd;
	struct stat st;
	sem_t *sem = SEM_FAILED;

	if (!shared_mem_size)
		return 0;

	if (!stat(HSAKMT_SHM_PATH, &st)) {
		pr_debug("%s already exists\n", HSAKMT_SHM_PATH);
	} else {
		pr_info("Warning:%s was missing. Re-creating new file but we may lose perf counters\n",
			HSAKMT_SHM_PATH);
		fd = shm_open(HSAKMT_SHM, O_CREAT | O_RDWR, 0666);

		ret = ftruncate(fd, shared_mem_size);
		if (ret < 0) {
			pr_err("Failed to truncate shared mem %s\n", HSAKMT_SHM);
			close(fd);
			return -errno;
		}

		ret = write(fd, &shared_mem_magic, sizeof(shared_mem_magic));
		if (ret != sizeof(shared_mem_magic)) {
			pr_perror("Failed to restore shared mem magic");
			close(fd);
			return -errno;
		}

		close(fd);
	}

	sem = sem_open(HSAKMT_SEM, O_CREAT, 0666, 1);
	if (sem == SEM_FAILED) {
		pr_perror("Failed to create %s", HSAKMT_SEM);
		return -EACCES;
	}
	sem_close(sem);
	return 0;
}

static int unpause_process(int fd)
{
	int ret = 0;
	struct kfd_ioctl_criu_args args = { 0 };

	args.op = KFD_CRIU_OP_UNPAUSE;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args);
	if (ret) {
		pr_perror("Failed to unpause process");
		goto exit;
	}

	// Reset the KFD FD
	kfd_checkpoint_fd = -1;
	sys_close_drm_render_devices(&src_topology);

exit:
	pr_info("Process unpaused %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);

	return ret;
}

static int save_devices(int fd, struct kfd_ioctl_criu_args *args, struct kfd_criu_device_bucket *device_buckets,
			CriuKfd *e)
{
	int ret = 0;

	pr_debug("Dumping %d devices\n", args->num_devices);

	/* When checkpointing on a node where there was already a checkpoint-restore before, the
	 * user_gpu_id and actual_gpu_id will be different.
	 *
	 * We store the user_gpu_id in the stored image files so that the stored images always have
	 * the gpu_id's of the node where the application was first launched.
	 */
	for (int i = 0; i < args->num_devices; i++)
		maps_add_gpu_entry(&checkpoint_maps, device_buckets[i].actual_gpu_id, device_buckets[i].user_gpu_id);

	e->num_of_gpus = args->num_devices;
	e->num_of_cpus = src_topology.num_nodes - args->num_devices;

	/* The ioctl will only return entries for GPUs, but we also store entries for CPUs and the
	 * information for CPUs is obtained from parsing system topology
	 */
	ret = allocate_device_entries(e, src_topology.num_nodes);
	if (ret)
		goto exit;

	pr_debug("Number of CPUs:%d GPUs:%d\n", e->num_of_cpus, e->num_of_gpus);

	/* Store topology information that was obtained from parsing /sys/class/kfd/kfd/topology/ */
	ret = topology_to_devinfo(&src_topology, &checkpoint_maps, e->device_entries);
	if (ret)
		goto exit;

exit:
	pr_info("Dumped devices %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int save_bos(int id, int fd, struct kfd_ioctl_criu_args *args, struct kfd_criu_bo_bucket *bo_buckets, CriuKfd *e)
{
	struct thread_data *thread_datas;
	int ret = 0, i;

	pr_debug("Dumping %d BOs\n", args->num_bos);

	thread_datas = xzalloc(sizeof(*thread_datas) * e->num_of_gpus);
	if (!thread_datas) {
		ret = -ENOMEM;
		goto exit;
	}

	e->num_of_bos = args->num_bos;
	ret = allocate_bo_entries(e, e->num_of_bos, bo_buckets);
	if (ret)
		goto exit;

	for (i = 0; i < e->num_of_bos; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		KfdBoEntry *boinfo = e->bo_entries[i];

		boinfo->gpu_id = bo_bucket->gpu_id;
		boinfo->addr = bo_bucket->addr;
		boinfo->size = bo_bucket->size;
		boinfo->offset = bo_bucket->offset;
		boinfo->alloc_flags = bo_bucket->alloc_flags;
	}

	for (int i = 0; i < e->num_of_gpus; i++) {
		struct tp_node *dev;
		int ret_thread = 0;

		dev = sys_get_node_by_index(&src_topology, i);
		if (!dev) {
			ret = -ENODEV;
			goto exit;
		}

		thread_datas[i].id = id;
		thread_datas[i].gpu_id = dev->gpu_id;
		thread_datas[i].bo_buckets = bo_buckets;
		thread_datas[i].bo_entries = e->bo_entries;
		thread_datas[i].pid = e->pid;
		thread_datas[i].num_of_bos = args->num_bos;
		thread_datas[i].drm_fd = node_get_drm_render_device(dev);
		if (thread_datas[i].drm_fd < 0) {
			ret = thread_datas[i].drm_fd;
			goto exit;
		}

		ret_thread = pthread_create(&thread_datas[i].thread, NULL, dump_bo_contents, (void *)&thread_datas[i]);
		if (ret_thread) {
			pr_err("Failed to create thread[%i]\n", i);
			ret = -ret_thread;
			goto exit;
		}
	}

	for (int i = 0; i < e->num_of_gpus; i++) {
		pthread_join(thread_datas[i].thread, NULL);
		pr_info("Thread[0x%x] finished ret:%d\n", thread_datas[i].gpu_id, thread_datas[i].ret);

		if (thread_datas[i].ret) {
			ret = thread_datas[i].ret;
			goto exit;
		}
	}
exit:
	for (int i = 0; i < e->num_of_bos; i++) {
		if (bo_buckets[i].dmabuf_fd != KFD_INVALID_FD)
			close(bo_buckets[i].dmabuf_fd);
	}

	xfree(thread_datas);
	pr_info("Dumped bos %s (ret:%d)\n", ret ? "failed" : "ok", ret);
	return ret;
}

bool kernel_supports_criu(int fd)
{
	struct kfd_ioctl_get_version_args args = { 0 };
	bool close_fd = false, ret = true;

	if (fd < 0) {
		fd = open(AMDGPU_KFD_DEVICE, O_RDONLY);
		if (fd < 0) {
			pr_perror("failed to open kfd in plugin");
			return false;
		}
		close_fd = true;
	}

	if (kmtIoctl(fd, AMDKFD_IOC_GET_VERSION, &args) == -1) {
		pr_perror("Failed to call get version ioctl");
		ret = false;
		goto exit;
	}

	pr_debug("Kernel IOCTL version:%d.%02d\n", args.major_version, args.minor_version);

	if (args.major_version != KFD_IOCTL_MAJOR_VERSION || args.minor_version < MIN_KFD_IOCTL_MINOR_VERSION) {
		pr_err("CR not supported on current kernel (current:%02d.%02d min:%02d.%02d)\n", args.major_version,
		       args.minor_version, KFD_IOCTL_MAJOR_VERSION, MIN_KFD_IOCTL_MINOR_VERSION);
		ret = false;
		goto exit;
	}

exit:
	if (close_fd)
		close(fd);

	return ret;
}

int amdgpu_plugin_dump_file(int fd, int id)
{
	struct kfd_ioctl_criu_args args = { 0 };
	char img_path[PATH_MAX];
	struct stat st, st_kfd;
	unsigned char *buf;
	CriuKfd *e = NULL;
	int ret = 0;
	size_t len;

	if (fstat(fd, &st) == -1) {
		pr_perror("fstat error");
		return -1;
	}

	ret = stat(AMDGPU_KFD_DEVICE, &st_kfd);
	if (ret == -1) {
		pr_perror("fstat error for /dev/kfd");
		return -1;
	}

	if (topology_parse(&src_topology, "Checkpoint"))
		return -1;

	/* We call topology_determine_iolinks to validate io_links. If io_links are not valid
	 * we do not store them inside the checkpointed images
	 */
	if (topology_determine_iolinks(&src_topology)) {
		pr_err("Failed to determine iolinks from topology\n");
		return -1;
	}

	/* Initialize number of device files that will be checkpointed */
	init_gpu_count(&src_topology);

	/* Check whether this plugin was called for kfd or render nodes */
	if (major(st.st_rdev) != major(st_kfd.st_rdev) || minor(st.st_rdev) != 0) {

		/* This is RenderD dumper plugin, for now just save renderD
		 * minor number to be used during restore. In later phases this
		 * needs to save more data for video decode etc.
		 */
		ret = amdgpu_plugin_drm_dump_file(fd, id, &st);
		if (ret)
			return ret;

		/* Invoke unpause process if needed */
		decrement_checkpoint_count();
		if (checkpoint_is_complete()) {
			ret = unpause_process(kfd_checkpoint_fd);
		}

		/* Need to return success here so that criu can call plugins for renderD nodes */
		return ret;
	}

	pr_info("%s() called for fd = %d\n", __func__, major(st.st_rdev));

	/* KFD only allows ioctl calls from the same process that opened the KFD file descriptor.
	 * The existing /dev/kfd file descriptor that is passed in is only allowed to do IOCTL calls with
	 * CAP_CHECKPOINT_RESTORE/CAP_SYS_ADMIN. So kernel_supports_criu() needs to open its own file descriptor to
	 * perform the AMDKFD_IOC_GET_VERSION ioctl.
	 */
	if (!kernel_supports_criu(-1))
		return -ENOTSUP;

	args.op = KFD_CRIU_OP_PROCESS_INFO;
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args) == -1) {
		pr_perror("Failed to call process info ioctl");
		ret = -1;
		goto exit;
	}

	pr_info("devices:%" PRIu32 " bos:%" PRIu32 " objects:%" PRIu32 " priv_data:%" PRIu64 "\n",
		args.num_devices, args.num_bos, args.num_objects, args.priv_data_size);

	e = xmalloc(sizeof(*e));
	if (!e) {
		pr_err("Failed to allocate proto structure\n");
		ret = -ENOMEM;
		goto exit;
	}

	criu_kfd__init(e);
	e->pid = args.pid;

	args.devices = (uintptr_t)xzalloc((args.num_devices * sizeof(struct kfd_criu_device_bucket)));
	if (!args.devices) {
		ret = -ENOMEM;
		goto exit;
	}

	args.bos = (uintptr_t)xzalloc((args.num_bos * sizeof(struct kfd_criu_bo_bucket)));
	if (!args.bos) {
		ret = -ENOMEM;
		goto exit;
	}

	args.priv_data = (uintptr_t)xzalloc((args.priv_data_size));
	if (!args.priv_data) {
		ret = -ENOMEM;
		goto exit;
	}

	args.op = KFD_CRIU_OP_CHECKPOINT;
	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args);
	if (ret) {
		pr_perror("Failed to call dumper (process) ioctl");
		goto exit;
	}

	ret = save_devices(fd, &args, (struct kfd_criu_device_bucket *)args.devices, e);
	if (ret)
		goto exit;

	ret = save_bos(id, fd, &args, (struct kfd_criu_bo_bucket *)args.bos, e);
	if (ret)
		goto exit;

	e->num_of_objects = args.num_objects;

	e->priv_data.data = (void *)args.priv_data;
	e->priv_data.len = args.priv_data_size;

	ret = check_hsakmt_shared_mem(&e->shared_mem_size, &e->shared_mem_magic);
	if (ret)
		goto exit;

	snprintf(img_path, sizeof(img_path), IMG_KFD_FILE, id);
	pr_info("img_path = %s\n", img_path);

	len = criu_kfd__get_packed_size(e);

	pr_info("Len = %ld\n", len);

	buf = xmalloc(len);
	if (!buf) {
		pr_perror("Failed to allocate memory to store protobuf");
		ret = -ENOMEM;
		goto exit;
	}

	criu_kfd__pack(e, buf);

	ret = write_img_file(img_path, buf, len);

	xfree(buf);

exit:
	/* Restore all queues if conditions permit */
	kfd_checkpoint_fd = fd;
	decrement_checkpoint_count();
	if (checkpoint_is_complete()) {
		ret = unpause_process(fd);
	}

	xfree((void *)args.devices);
	xfree((void *)args.bos);
	xfree((void *)args.priv_data);

	free_e(e);

	if (ret)
		pr_err("Failed to dump (ret:%d)\n", ret);
	else
		pr_info("Dump successful\n");

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, amdgpu_plugin_dump_file)

/* Restore per-device information */
static int restore_devices(struct kfd_ioctl_criu_args *args, CriuKfd *e)
{
	struct kfd_criu_device_bucket *device_buckets;
	int ret = 0, bucket_index = 0;

	pr_debug("Restoring %d devices\n", e->num_of_gpus);

	args->num_devices = e->num_of_gpus;
	device_buckets = xzalloc(sizeof(*device_buckets) * args->num_devices);
	if (!device_buckets)
		return -ENOMEM;

	args->devices = (uintptr_t)device_buckets;

	for (int entries_i = 0; entries_i < e->num_of_cpus + e->num_of_gpus; entries_i++) {
		struct kfd_criu_device_bucket *device_bucket;
		KfdDeviceEntry *devinfo = e->device_entries[entries_i];
		struct tp_node *tp_node;

		if (!devinfo->gpu_id)
			continue;

		device_bucket = &device_buckets[bucket_index++];

		device_bucket->user_gpu_id = devinfo->gpu_id;
		device_bucket->actual_gpu_id = maps_get_dest_gpu(&restore_maps, devinfo->gpu_id);
		if (!device_bucket->actual_gpu_id) {
			ret = -ENODEV;
			goto exit;
		}

		tp_node = sys_get_node_by_gpu_id(&dest_topology, device_bucket->actual_gpu_id);
		if (!tp_node) {
			ret = -ENODEV;
			goto exit;
		}

		device_bucket->drm_fd = node_get_drm_render_device(tp_node);
		if (device_bucket->drm_fd < 0) {
			pr_perror("Can't pass NULL drm render fd to driver");
			goto exit;
		} else {
			pr_info("passing drm render fd = %d to driver\n", device_bucket->drm_fd);
		}
	}

exit:
	pr_info("Restore devices %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int restore_bos(struct kfd_ioctl_criu_args *args, CriuKfd *e)
{
	struct kfd_criu_bo_bucket *bo_buckets;

	pr_debug("Restoring %ld BOs\n", e->num_of_bos);

	args->num_bos = e->num_of_bos;
	bo_buckets = xzalloc(sizeof(*bo_buckets) * args->num_bos);
	if (!bo_buckets)
		return -ENOMEM;

	args->bos = (uintptr_t)bo_buckets;

	for (int i = 0; i < args->num_bos; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		KfdBoEntry *bo_entry = e->bo_entries[i];

		bo_bucket->gpu_id = bo_entry->gpu_id;
		bo_bucket->addr = bo_entry->addr;
		bo_bucket->size = bo_entry->size;
		bo_bucket->offset = bo_entry->offset;
		bo_bucket->alloc_flags = bo_entry->alloc_flags;

		plugin_log_msg("BO [%d] gpu_id:%x addr:%llx size:%llx offset:%llx\n", i, bo_bucket->gpu_id,
			       bo_bucket->addr, bo_bucket->size, bo_bucket->offset);
	}

	pr_info("Restore BOs Ok\n");
	return 0;
}

static int restore_bo_data(int id, struct kfd_criu_bo_bucket *bo_buckets, CriuKfd *e)
{
	struct thread_data *thread_datas = NULL;
	int thread_i, ret = 0;
	int offset = 0;

	for (int i = 0; i < e->num_of_bos; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		struct tp_node *tp_node;

		if (bo_bucket->alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT |
					      KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP | KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL)) {
			struct vma_metadata *vma_md;
			uint32_t target_gpu_id; /* actual gpu_id where the BO will be restored */

			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md) {
				ret = -ENOMEM;
				goto exit;
			}

			memset(vma_md, 0, sizeof(*vma_md));

			vma_md->old_pgoff = bo_bucket->offset;
			vma_md->vma_entry = bo_bucket->addr;

			target_gpu_id = maps_get_dest_gpu(&restore_maps, bo_bucket->gpu_id);

			tp_node = sys_get_node_by_gpu_id(&dest_topology, target_gpu_id);
			if (!tp_node) {
				pr_err("Failed to find node with gpu_id:0x%04x\n", target_gpu_id);
				ret = -ENODEV;
				goto exit;
			}

			vma_md->new_minor = tp_node->drm_render_minor;
			vma_md->new_pgoff = bo_bucket->restored_offset;
			vma_md->fd = node_get_drm_render_device(tp_node);

			plugin_log_msg("adding vma_entry:addr:0x%lx old-off:0x%lx "
				       "new_off:0x%lx new_minor:%d\n",
				       vma_md->vma_entry, vma_md->old_pgoff, vma_md->new_pgoff, vma_md->new_minor);

			list_add_tail(&vma_md->list, &update_vma_info_list);
		}
	}

	if (!parallel_disabled) {
		parallel_restore_cmd restore_cmd;
		pr_info("Begin to send parallel restore cmd\n");
		ret = init_parallel_restore_cmd(e->num_of_bos, id, e->num_of_gpus, &restore_cmd);
		if (ret)
			goto exit_parallel;

		for (int i = 0; i < e->num_of_gpus + e->num_of_cpus; i++) {
			uint32_t target_gpu_id;
			struct tp_node *dev;

			if (!e->device_entries[i]->gpu_id)
				continue;

			target_gpu_id = maps_get_dest_gpu(&restore_maps, e->device_entries[i]->gpu_id);
			dev = sys_get_node_by_gpu_id(&dest_topology, target_gpu_id);
			if (!dev) {
				pr_err("Failed to find node with gpu_id:0x%04x\n", target_gpu_id);
				ret = -ENODEV;
				goto exit_parallel;
			}
			parallel_restore_gpu_id_add(e->device_entries[i]->gpu_id, dev->drm_render_minor, &restore_cmd);

			for (int j = 0; j < e->num_of_bos; j++) {
				if (bo_buckets[j].gpu_id != e->device_entries[i]->gpu_id)
					continue;
				if (bo_buckets[j].alloc_flags &
				    (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {
					parallel_restore_bo_add(bo_buckets[j].dmabuf_fd, bo_buckets[j].gpu_id,
								bo_buckets[j].size, offset, &restore_cmd);
					offset += bo_buckets[j].size;
				}
			}
		}
		ret = send_parallel_restore_cmd(&restore_cmd);
exit_parallel:
		free_parallel_restore_cmd(&restore_cmd);
	} else {
		thread_datas = xzalloc(sizeof(*thread_datas) * e->num_of_gpus);
		if (!thread_datas) {
			ret = -ENOMEM;
			goto exit;
		}

		thread_i = 0;
		for (int i = 0; i < e->num_of_gpus + e->num_of_cpus; i++) {
			struct tp_node *dev;
			int ret_thread = 0;
			uint32_t target_gpu_id;

			if (!e->device_entries[i]->gpu_id)
				continue;

			/* e->device_entries[i]->gpu_id is user_gpu_id, target_gpu_id is actual_gpu_id */
			target_gpu_id = maps_get_dest_gpu(&restore_maps, e->device_entries[i]->gpu_id);

			/* We need the fd for actual_gpu_id */
			dev = sys_get_node_by_gpu_id(&dest_topology, target_gpu_id);
			if (!dev) {
				pr_err("Failed to find node with gpu_id:0x%04x\n", target_gpu_id);
				ret = -ENODEV;
				goto exit;
			}

			thread_datas[thread_i].id = id;
			thread_datas[thread_i].gpu_id = e->device_entries[i]->gpu_id;
			thread_datas[thread_i].bo_buckets = bo_buckets;
			thread_datas[thread_i].bo_entries = e->bo_entries;
			thread_datas[thread_i].pid = e->pid;
			thread_datas[thread_i].num_of_bos = e->num_of_bos;

			thread_datas[thread_i].drm_fd = node_get_drm_render_device(dev);
			if (thread_datas[thread_i].drm_fd < 0) {
				ret = -thread_datas[thread_i].drm_fd;
				goto exit;
			}

			ret_thread = pthread_create(&thread_datas[thread_i].thread, NULL, restore_bo_contents,
						    (void *)&thread_datas[thread_i]);
			if (ret_thread) {
				pr_err("Failed to create thread[%i] ret:%d\n", thread_i, ret_thread);
				ret = -ret_thread;
				goto exit;
			}
			thread_i++;
		}

		for (int i = 0; i < e->num_of_gpus; i++) {
			pthread_join(thread_datas[i].thread, NULL);
			pr_info("Thread[0x%x] finished ret:%d\n", thread_datas[i].gpu_id, thread_datas[i].ret);

			if (thread_datas[i].ret) {
				ret = thread_datas[i].ret;
				goto exit;
			}
		}
	}
exit:
	for (int i = 0; i < e->num_of_bos; i++) {
		if (bo_buckets[i].dmabuf_fd != KFD_INVALID_FD)
			close(bo_buckets[i].dmabuf_fd);
	}
	if (thread_datas)
		xfree(thread_datas);
	return ret;
}

int amdgpu_plugin_restore_file(int id)
{
	int ret = 0, fd;
	char img_path[PATH_MAX];
	unsigned char *buf;
	CriuRenderNode *rd;
	CriuKfd *e = NULL;
	struct kfd_ioctl_criu_args args = { 0 };
	size_t img_size;
	FILE *img_fp = NULL;

	if (plugin_disabled)
		return -ENOTSUP;

	pr_info("Initialized kfd plugin restorer with ID = %d\n", id);

	snprintf(img_path, sizeof(img_path), IMG_KFD_FILE, id);

	img_fp = open_img_file(img_path, false, &img_size);
	if (!img_fp) {
		struct tp_node *tp_node;
		uint32_t target_gpu_id;

		/* This is restorer plugin for renderD nodes. Criu doesn't guarantee that they will
		 * be called before the plugin is called for kfd file descriptor.
		 * TODO: Currently, this code will only work if this function is called for /dev/kfd
		 * first as we assume restore_maps is already filled. Need to fix this later.
		 */
		snprintf(img_path, sizeof(img_path), IMG_DRM_FILE, id);
		pr_info("Restoring RenderD %s\n", img_path);

		img_fp = open_img_file(img_path, false, &img_size);
		if (!img_fp)
			return -EINVAL;

		pr_debug("RenderD Image file size:%ld\n", img_size);
		buf = xmalloc(img_size);
		if (!buf) {
			pr_perror("Failed to allocate memory");
			return -ENOMEM;
		}

		ret = read_fp(img_fp, buf, img_size);
		if (ret) {
			pr_perror("Unable to read from %s", img_path);
			xfree(buf);
			return -1;
		}

		rd = criu_render_node__unpack(NULL, img_size, buf);
		if (rd == NULL) {
			pr_perror("Unable to parse the RenderD message %d", id);
			xfree(buf);
			fclose(img_fp);
			return -1;
		}
		fclose(img_fp);

		pr_info("render node gpu_id = 0x%04x\n", rd->gpu_id);

		target_gpu_id = maps_get_dest_gpu(&restore_maps, rd->gpu_id);
		if (!target_gpu_id) {
			fd = -ENODEV;
			goto fail;
		}

		tp_node = sys_get_node_by_gpu_id(&dest_topology, target_gpu_id);
		if (!tp_node) {
			fd = -ENODEV;
			goto fail;
		}

		pr_info("render node destination gpu_id = 0x%04x\n", tp_node->gpu_id);

		fd = node_get_drm_render_device(tp_node);
		if (fd < 0)
			pr_err("Failed to open render device (minor:%d)\n", tp_node->drm_render_minor);
	fail:
		criu_render_node__free_unpacked(rd, NULL);
		xfree(buf);
		/*
		 * We need to use the file descriptor used to create the BOs for mmap later, otherwise the kernel DRM
		 * drivers will not allow the mmap. Therefore, we keep a copy of the file descriptor (stored in tp_node)
		 * so that we can return it in amdgpu_plugin_update_vmamap later. Also, CRIU core will dup and close the
		 * returned fd after this function returns, and this will make our fd invalid. So we return a dup'ed
		 * copy of the fd. CRIU core owns the duplicated returned fd, and amdgpu_plugin owns the fd stored in
		 * tp_node.
		 */
		fd = dup(fd);
		if (fd == -1) {
			pr_perror("unable to duplicate the render fd");
			return -1;
		}
		return fd;
	}

	fd = open(AMDGPU_KFD_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	pr_info("Opened kfd, fd = %d\n", fd);

	if (!kernel_supports_criu(fd))
		return -ENOTSUP;

	pr_info("KFD Image file size:%ld\n", img_size);
	buf = xmalloc(img_size);
	if (!buf) {
		fclose(img_fp);
		return -ENOMEM;
	}

	ret = read_fp(img_fp, buf, img_size);
	if (ret) {
		pr_perror("Unable to read from %s", img_path);
		fclose(img_fp);
		xfree(buf);
		return ret;
	}

	fclose(img_fp);
	e = criu_kfd__unpack(NULL, img_size, buf);
	if (e == NULL) {
		pr_err("Unable to parse the KFD message %#x\n", id);
		xfree(buf);
		return -1;
	}

	plugin_log_msg("read image file data\n");

	/*
	 * Initialize fd_next to be 1 greater than the biggest file descriptor in use by the target restore process.
	 * This way, we know that the file descriptors we store will not conflict with file descriptors inside core
	 * CRIU.
	 */
	fd_next = find_unused_fd_pid(e->pid);
	if (fd_next <= 0) {
		pr_err("Failed to find unused fd (fd:%d)\n", fd_next);
		ret = -EINVAL;
		goto exit;
	}

	ret = devinfo_to_topology(e->device_entries, e->num_of_gpus + e->num_of_cpus, &src_topology);
	if (ret) {
		pr_err("Failed to convert stored device information to topology\n");
		ret = -EINVAL;
		goto exit;
	}

	ret = topology_parse(&dest_topology, "Local");
	if (ret) {
		pr_err("Failed to parse local system topology\n");
		goto exit;
	}

	ret = set_restore_gpu_maps(&src_topology, &dest_topology, &restore_maps);
	if (ret) {
		pr_err("Failed to map GPUs\n");
		goto exit;
	}

	ret = restore_devices(&args, e);
	if (ret)
		goto exit;

	ret = restore_bos(&args, e);
	if (ret)
		goto exit;

	args.num_objects = e->num_of_objects;
	args.priv_data_size = e->priv_data.len;
	args.priv_data = (uintptr_t)e->priv_data.data;

	args.op = KFD_CRIU_OP_RESTORE;
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args) == -1) {
		pr_perror("Restore ioctl failed");
		ret = -1;
		goto exit;
	}

	ret = restore_bo_data(id, (struct kfd_criu_bo_bucket *)args.bos, e);
	if (ret)
		goto exit;

	ret = restore_hsakmt_shared_mem(e->shared_mem_size, e->shared_mem_magic);

exit:
	if (e)
		criu_kfd__free_unpacked(e, NULL);

	xfree((void *)args.devices);
	xfree((void *)args.bos);
	xfree(buf);

	if (ret) {
		pr_err("Failed to restore (ret:%d)\n", ret);
		fd = ret;
	} else {
		pr_info("Restore successful (fd:%d)\n", fd);
	}

	return fd;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, amdgpu_plugin_restore_file)

/* return 0 if no match found
 * return -1 for error.
 * return 1 if vmap map must be adjusted.
 */
int amdgpu_plugin_update_vmamap(const char *in_path, const uint64_t addr, const uint64_t old_offset,
				uint64_t *new_offset, int *updated_fd)
{
	struct vma_metadata *vma_md;
	char path[PATH_MAX];
	char *p_begin;
	char *p_end;
	bool is_kfd = false, is_renderD = false;

	if (plugin_disabled)
		return -ENOTSUP;

	plugin_log_msg("Enter %s\n", __func__);

	strncpy(path, in_path, sizeof(path));

	p_begin = path;
	p_end = p_begin + strlen(path);

	/*
	 * Paths sometimes have double forward slashes (e.g //dev/dri/renderD*)
	 * replace all '//' with '/'.
	 */
	while (p_begin < p_end - 1) {
		if (*p_begin == '/' && *(p_begin + 1) == '/')
			memmove(p_begin, p_begin + 1, p_end - p_begin);
		else
			p_begin++;
	}

	if (!strncmp(path, "/dev/dri/renderD", strlen("/dev/dri/renderD")))
		is_renderD = true;

	if (!strcmp(path, AMDGPU_KFD_DEVICE))
		is_kfd = true;

	if (!is_renderD && !is_kfd) {
		pr_info("Skipping unsupported path:%s addr:%lx old_offset:%lx\n", in_path, addr, old_offset);
		return 0;
	}

	list_for_each_entry(vma_md, &update_vma_info_list, list) {
		if (addr == vma_md->vma_entry && old_offset == vma_md->old_pgoff) {
			*new_offset = vma_md->new_pgoff;

			*updated_fd = -1;
			if (is_renderD) {
				int fd = dup(vma_md->fd);
				if (fd == -1) {
					pr_perror("unable to duplicate the render fd");
					return -1;
				}
				*updated_fd = fd;
			}

			plugin_log_msg("old_pgoff=0x%lx new_pgoff=0x%lx fd=%d\n", vma_md->old_pgoff, vma_md->new_pgoff,
				       *updated_fd);

			return 1;
		}
	}
	pr_info("No match for addr:0x%lx offset:%lx\n", addr, old_offset);
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, amdgpu_plugin_update_vmamap)

int amdgpu_plugin_resume_devices_late(int target_pid)
{
	struct kfd_ioctl_criu_args args = { 0 };
	int fd, exit_code = 0;

	if (plugin_disabled)
		return -ENOTSUP;

	if (!parallel_disabled) {
		pr_info("Close parallel restore server\n");
		if (close_parallel_restore_server()) {
			pr_err("Close parallel restore server fail\n");
			return -1;
		}

		exit_code = pthread_join(parallel_thread, NULL);
		if (exit_code) {
			pr_err("Failed to join parallel thread ret:%d\n", exit_code);
			return -1;
		}
		if (parallel_thread_result) {
			pr_err("Parallel restore fail\n");
			return parallel_thread_result;
		}
	}

	pr_info("Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open(AMDGPU_KFD_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -ENOTSUP;
	}

	args.pid = target_pid;
	args.op = KFD_CRIU_OP_RESUME;
	pr_info("Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args) == -1) {
		if (errno == ESRCH) {
			pr_info("Pid %d has no kfd process info\n", target_pid);
			exit_code = -ENOTSUP;
		} else {
			pr_perror("restore late ioctl failed");
			exit_code = -1;
		}
	}

	close(fd);
	return exit_code;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, amdgpu_plugin_resume_devices_late)

int sdma_copy_bo_helper(uint64_t size, int fd, FILE *storage_fp, void *buffer, size_t buffer_size,
			amdgpu_device_handle h_dev, uint64_t max_copy_size, enum sdma_op_type type)
{
	return sdma_copy_bo((struct kfd_criu_bo_bucket){ 0, size, 0, 0, 0, 0, fd, 0 }, storage_fp, buffer,
			    buffer_size, h_dev, max_copy_size, SDMA_OP_VRAM_WRITE);
}

int init_dev(int dev_minor, amdgpu_device_handle *h_dev, uint64_t *max_copy_size)
{
	int ret = 0;
	int drm_fd = -1;
	uint32_t major, minor;

	struct amdgpu_gpu_info gpu_info = { 0 };

	drm_fd = open_drm_render_device(dev_minor);
	if (drm_fd < 0) {
		return drm_fd;
	}

	ret = amdgpu_device_initialize(drm_fd, &major, &minor, h_dev);
	if (ret) {
		pr_perror("Failed to initialize device");
		goto err;
	}

	ret = amdgpu_query_gpu_info(*h_dev, &gpu_info);
	if (ret) {
		pr_perror("failed to query gpuinfo via libdrm");
		goto err;
	}
	*max_copy_size = (gpu_info.family_id >= AMDGPU_FAMILY_AI) ? SDMA_LINEAR_COPY_MAX_SIZE :
								    SDMA_LINEAR_COPY_MAX_SIZE - 1;
	return 0;
err:
	amdgpu_device_deinitialize(*h_dev);
	return ret;
}

FILE *get_bo_contents_fp(int id, int gpu_id, size_t tot_size)
{
	char img_path[PATH_MAX];
	size_t image_size = 0;
	FILE *bo_contents_fp = NULL;

	snprintf(img_path, sizeof(img_path), IMG_KFD_PAGES_FILE, id, gpu_id);
	bo_contents_fp = open_img_file(img_path, false, &image_size);
	if (!bo_contents_fp) {
		pr_perror("Cannot fopen %s", img_path);
		return NULL;
	}

	if (tot_size != image_size) {
		pr_err("%s size mismatch (current:%ld:expected:%ld)\n", img_path, image_size, tot_size);
		fclose(bo_contents_fp);
		return NULL;
	}
	return bo_contents_fp;
}

struct parallel_thread_data {
	pthread_t thread;
	uint32_t gpu_id;
	int minor;
	parallel_restore_cmd *restore_cmd;
	int ret;
};

void *parallel_restore_bo_contents(void *_thread_data)
{
	struct parallel_thread_data *thread_data = (struct parallel_thread_data *)_thread_data;
	amdgpu_device_handle h_dev;
	uint64_t max_copy_size;
	size_t total_bo_size = 0, max_bo_size = 0, buffer_size = 0;
	FILE *bo_contents_fp = NULL;
	parallel_restore_entry *entry;
	parallel_restore_cmd *restore_cmd = thread_data->restore_cmd;
	int ret = 0;
	int offset = 0;
	void *buffer = NULL;

	ret = init_dev(thread_data->minor, &h_dev, &max_copy_size);
	if (ret) {
		goto err;
	}

	for (int i = 0; i < restore_cmd->cmd_head.entry_num; i++) {
		if (restore_cmd->entries[i].gpu_id == thread_data->gpu_id) {
			total_bo_size += restore_cmd->entries[i].size;
			max_bo_size = max(restore_cmd->entries[i].size, max_bo_size);
		}
	}

	buffer_size = kfd_max_buffer_size > 0 ? min(kfd_max_buffer_size, max_bo_size) : max_bo_size;

	bo_contents_fp = get_bo_contents_fp(restore_cmd->cmd_head.id, thread_data->gpu_id, total_bo_size);
	if (bo_contents_fp == NULL) {
		ret = -1;
		goto err_sdma;
	}
	offset = ftell(bo_contents_fp);

	posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), buffer_size);
	if (!buffer) {
		pr_perror("Failed to alloc aligned memory. Consider setting KFD_MAX_BUFFER_SIZE.");
		ret = -ENOMEM;
		goto err_sdma;
	}

	for (int i = 0; i < restore_cmd->cmd_head.entry_num; i++) {
		if (restore_cmd->entries[i].gpu_id != thread_data->gpu_id)
			continue;

		entry = &restore_cmd->entries[i];
		fseek(bo_contents_fp, entry->read_offset + offset, SEEK_SET);
		ret = sdma_copy_bo_helper(entry->size, restore_cmd->fds_write[entry->write_id], bo_contents_fp, buffer,
					  buffer_size, h_dev, max_copy_size, SDMA_OP_VRAM_WRITE);
		if (ret) {
			pr_err("Failed to fill the BO using sDMA: bo_buckets[%d]\n", i);
			goto err_sdma;
		}
	}

err_sdma:
	if (bo_contents_fp)
		fclose(bo_contents_fp);
	if (buffer)
		xfree(buffer);
	amdgpu_device_deinitialize(h_dev);
err:
	thread_data->ret = ret;
	return NULL;
}

void *restore_device_parallel_worker(void *arg)
{
	while (1) {
		parallel_restore_cmd restore_cmd = { 0 };
		struct parallel_thread_data *thread_datas = NULL;
		int ret;
		int error_occurred = 0, join_ret = 0, created_threads = 0;

		ret = recv_parallel_restore_cmd(&restore_cmd);
		if (ret) {
			if (ret == 1) {
				*(int *)arg = 0;
				goto exit;
			}
			goto err;
		}

		thread_datas = xzalloc(sizeof(*thread_datas) * restore_cmd.cmd_head.gpu_num);
		if (!thread_datas) {
			ret = -ENOMEM;
			goto err;
		}

		for (; created_threads < restore_cmd.cmd_head.gpu_num; created_threads++) {
			thread_datas[created_threads].gpu_id = restore_cmd.gpu_ids[created_threads].gpu_id;
			thread_datas[created_threads].minor = restore_cmd.gpu_ids[created_threads].minor;
			thread_datas[created_threads].restore_cmd = &restore_cmd;

			ret = pthread_create(&thread_datas[created_threads].thread, NULL, parallel_restore_bo_contents,
					     (void *)&thread_datas[created_threads]);
			if (ret) {
				pr_err("Failed to create thread[0x%x] ret:%d\n", thread_datas[created_threads].gpu_id, ret);
				error_occurred = 1;
				break;
			}
		}

		for (int i = 0; i < created_threads; i++) {
			join_ret = pthread_join(thread_datas[i].thread, NULL);
			if (join_ret != 0) {
				pr_err("pthread_join failed for Thread[0x%x] ret:%d\n",
				       thread_datas[i].gpu_id, join_ret);
				if (!error_occurred) {
					ret = join_ret;
					error_occurred = 1;
				}
			}

			pr_info("Thread[0x%x] finished ret:%d\n", thread_datas[i].gpu_id, thread_datas[i].ret);

			/* Check thread return value */
			if (thread_datas[i].ret && !error_occurred) {
				ret = thread_datas[i].ret;
				error_occurred = 1;
			}
		}

		if (thread_datas)
			xfree(thread_datas);
err:
		free_parallel_restore_cmd(&restore_cmd);

		if (ret) {
			*(int *)arg = ret;
			return NULL;
		}
	}
exit:
	return NULL;
}

/*
 * While the background thread is running, some processing functions (e.g., stop_cgroupd)
 * in the main thread need to block SIGCHLD. To prevent interference from this background
 * thread, SIGCHLD is blocked in this thread.
 */
static int back_thread_create(pthread_t *newthread, void *(*f)(void *), void *arg)
{
	int ret = 0;
	sigset_t blockmask, oldmask;

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

	ret = pthread_create(newthread, NULL, f, arg);
	if (ret) {
		pr_err("Create worker thread fail: %d\n", ret);
		return -1;
	}

	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	return 0;
}

int amdgpu_plugin_post_forking(void)
{
	if (plugin_disabled)
		return -ENOTSUP;

	if (parallel_disabled)
		return 0;

	return back_thread_create(&parallel_thread, restore_device_parallel_worker, &parallel_thread_result);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__POST_FORKING, amdgpu_plugin_post_forking)