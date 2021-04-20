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

#include "criu-plugin.h"
#include "plugin.h"
#include "criu-amdgpu.pb-c.h"

#include "kfd_ioctl.h"
#include "xmalloc.h"
#include "criu-log.h"

#include "common/list.h"
#include "amdgpu_plugin_topology.h"

#define DRM_FIRST_RENDER_NODE 128
#define DRM_LAST_RENDER_NODE  255

#define AMDGPU_KFD_DEVICE "/dev/kfd"
#define PROCPIDMEM	  "/proc/%d/mem"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "amdgpu_plugin: "

#ifdef DEBUG
#define plugin_log_msg(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
#define plugin_log_msg(fmt, ...) \
	{                        \
	}
#endif

struct vma_metadata {
	struct list_head list;
	uint64_t old_pgoff;
	uint64_t new_pgoff;
	uint64_t vma_entry;
	uint32_t new_minor;
	int fd;
};

/************************************ Global Variables ********************************************/
struct tp_system src_topology;
struct tp_system dest_topology;

struct device_maps checkpoint_maps;
struct device_maps restore_maps;

static LIST_HEAD(update_vma_info_list);
/**************************************************************************************************/

int write_file(const char *file_path, const void *buf, const size_t buf_len)
{
	int fd;
	FILE *fp;
	size_t len_wrote;

	fd = openat(criu_get_image_dir(), file_path, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		pr_perror("Cannot open %s", file_path);
		return -errno;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		pr_perror("Cannot fdopen %s", file_path);
		return -errno;
	}

	len_wrote = fwrite(buf, 1, buf_len, fp);
	if (len_wrote != buf_len) {
		pr_perror("Unable to write %s (wrote:%ld buf_len:%ld)", file_path, len_wrote, buf_len);
		fclose(fp);
		return -EIO;
	}

	pr_info("Wrote file:%s (%ld bytes)\n", file_path, buf_len);
	/* this will also close fd */
	fclose(fp);
	return 0;
}

int read_file(const char *file_path, void *buf, const size_t buf_len)
{
	int fd;
	FILE *fp;
	size_t len_read;

	fd = openat(criu_get_image_dir(), file_path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Cannot open %s", file_path);
		return -errno;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		pr_perror("Cannot fdopen %s", file_path);
		return -errno;
	}

	len_read = fread(buf, 1, buf_len, fp);
	if (len_read != buf_len) {
		pr_perror("Unable to read %s", file_path);
		fclose(fp);
		return -EIO;
	}

	pr_info("Read file:%s (%ld bytes)\n", file_path, buf_len);

	/* this will also close fd */
	fclose(fp);
	return 0;
}

/* Call ioctl, restarting if it is interrupted */
int kmtIoctl(int fd, unsigned long request, void *arg)
{
	int ret;

	do {
		ret = ioctl(fd, request, arg);
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	if (ret == -1 && errno == EBADF)
		/* In case pthread_atfork didn't catch it, this will
		 * make any subsequent hsaKmt calls fail in CHECK_KFD_OPEN.
		 */
		pr_perror("KFD file descriptor not valid in this process");
	return ret;
}

static void free_e(CriuKfd *e)
{
	for (int i = 0; i < e->n_ev_entries; i++) {
		if (e->ev_entries[i]) {
			if (e->ev_entries[i]->private_data.data)
				xfree(e->ev_entries[i]->private_data.data);

			xfree(e->ev_entries[i]);
		}
	}

	for (int i = 0; i < e->n_q_entries; i++) {
		if (e->q_entries[i]) {
			if (e->q_entries[i]->private_data.data)
				xfree(e->q_entries[i]->private_data.data);

			xfree(e->q_entries[i]);
		}
	}

	for (int i = 0; i < e->n_bo_entries; i++) {
		if (e->bo_entries[i]) {
			if (e->bo_entries[i]->private_data.data)
				xfree(e->bo_entries[i]->private_data.data);

			if (e->bo_entries[i]->rawdata.data)
				xfree(e->bo_entries[i]->rawdata.data);

			xfree(e->bo_entries[i]);
		}
	}

	for (int i = 0; i < e->n_device_entries; i++) {
		if (e->device_entries[i]) {
			if (e->device_entries[i]->private_data.data)
				xfree(e->device_entries[i]->private_data.data);

			for (int j = 0; j < e->device_entries[i]->n_iolinks; j++)
				xfree(e->device_entries[i]->iolinks[j]);

			xfree(e->device_entries[i]);
		}
	}

	if (e->process_entry) {
		if (e->process_entry->private_data.data)
			xfree(e->process_entry->private_data.data);

		xfree(e->process_entry);
	}
	xfree(e);
}

static int allocate_process_entry(CriuKfd *e)
{
	ProcessEntry *entry = xzalloc(sizeof(*entry));

	if (!entry) {
		pr_err("Failed to allocate entry\n");
		return -ENOMEM;
	}

	process_entry__init(entry);
	e->process_entry = entry;
	return 0;
}

static int allocate_device_entries(CriuKfd *e, int num_of_devices)
{
	e->device_entries = xmalloc(sizeof(DeviceEntry *) * num_of_devices);
	if (!e->device_entries) {
		pr_err("Failed to allocate device_entries\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_of_devices; i++) {
		DeviceEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate entry\n");
			return -ENOMEM;
		}

		device_entry__init(entry);

		e->device_entries[i] = entry;
		e->n_device_entries++;
	}
	return 0;
}

static int allocate_bo_entries(CriuKfd *e, int num_bos, struct kfd_criu_bo_bucket *bo_bucket_ptr)
{
	e->bo_entries = xmalloc(sizeof(BoEntry *) * num_bos);
	if (!e->bo_entries) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	for (int i = 0; i < num_bos; i++) {
		BoEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		bo_entry__init(entry);

		if ((bo_bucket_ptr)[i].alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    (bo_bucket_ptr)[i].alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			entry->rawdata.data = xmalloc((bo_bucket_ptr)[i].size);
			entry->rawdata.len = (bo_bucket_ptr)[i].size;
		}

		e->bo_entries[i] = entry;
		e->n_bo_entries++;
	}
	return 0;
}

static int allocate_q_entries(CriuKfd *e, int num_queues)
{
	e->q_entries = xmalloc(sizeof(QEntry *) * num_queues);
	if (!e->q_entries) {
		pr_err("Failed to allocate q_entries\n");
		return -1;
	}

	for (int i = 0; i < num_queues; i++) {
		QEntry *entry = xzalloc(sizeof((*entry)));

		if (!entry) {
			pr_err("Failed to allocate queue entry\n");
			return -ENOMEM;
		}
		q_entry__init(entry);

		e->q_entries[i] = entry;
		e->n_q_entries++;
	}
	return 0;
}

static int allocate_ev_entries(CriuKfd *e, int num_events)
{
	e->ev_entries = xmalloc(sizeof(EvEntry *) * num_events);
	if (!e->ev_entries) {
		pr_err("Failed to allocate ev_entries\n");
		return -1;
	}

	for (int i = 0; i < num_events; i++) {
		EvEntry *entry = xzalloc(sizeof(*entry));

		if (!entry) {
			pr_err("Failed to allocate ev_entry\n");
			return -ENOMEM;
		}
		ev_entry__init(entry);

		e->ev_entries[i] = entry;
		e->n_ev_entries++;
	}
	return 0;
}

int topology_to_devinfo(struct tp_system *sys, struct device_maps *maps, DeviceEntry **deviceEntries)
{
	uint32_t devinfo_index = 0;
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		DeviceEntry *devinfo = deviceEntries[devinfo_index++];

		devinfo->node_id = node->id;

		if (NODE_IS_GPU(node)) {
			devinfo->gpu_id = maps_get_dest_gpu(&checkpoint_maps, node->gpu_id);
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

int devinfo_to_topology(DeviceEntry *devinfos[], uint32_t num_devices, struct tp_system *sys)
{
	for (int i = 0; i < num_devices; i++) {
		struct tp_node *node;
		DeviceEntry *devinfo = devinfos[i];

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

int amdgpu_plugin_init(int stage)
{
	pr_info("amdgpu_plugin: initialized:  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);

	topology_init(&src_topology);
	topology_init(&dest_topology);

	maps_init(&checkpoint_maps);
	maps_init(&restore_maps);

	return 0;
}

void amdgpu_plugin_fini(int stage, int ret)
{
	pr_info("amdgpu_plugin: finished  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);

	maps_free(&checkpoint_maps);
	maps_free(&restore_maps);

	topology_free(&src_topology);
	topology_free(&dest_topology);
}

CR_PLUGIN_REGISTER("amdgpu_plugin", amdgpu_plugin_init, amdgpu_plugin_fini)

int amdgpu_plugin_handle_device_vma(int fd, const struct stat *st_buf)
{
	struct stat st_kfd, st_dri_min;
	char img_path[128];
	int ret = 0;

	pr_debug("amdgpu_plugin: Enter %s\n", __func__);
	ret = stat(AMDGPU_KFD_DEVICE, &st_kfd);
	if (ret == -1) {
		pr_perror("stat error for /dev/kfd");
		return ret;
	}

	snprintf(img_path, sizeof(img_path), "/dev/dri/renderD%d", DRM_FIRST_RENDER_NODE);

	ret = stat(img_path, &st_dri_min);
	if (ret == -1) {
		pr_perror("stat error for %s", img_path);
		return ret;
	}

	if (major(st_buf->st_rdev) == major(st_kfd.st_rdev) || ((major(st_buf->st_rdev) == major(st_dri_min.st_rdev)) &&
								(minor(st_buf->st_rdev) >= minor(st_dri_min.st_rdev) &&
								 minor(st_buf->st_rdev) >= DRM_FIRST_RENDER_NODE))) {
		pr_debug("Known non-regular mapping, kfd-renderD%d -> OK\n", minor(st_buf->st_rdev));
		pr_debug("AMD KFD(maj) = %d, DRI(maj,min) = %d:%d VMA Device fd(maj,min) = %d:%d\n",
			 major(st_kfd.st_rdev), major(st_dri_min.st_rdev), minor(st_dri_min.st_rdev),
			 major(st_buf->st_rdev), minor(st_buf->st_rdev));
		/* VMA belongs to kfd */
		return 0;
	}

	pr_perror("amdgpu_plugin: Can't handle the VMA mapping");
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, amdgpu_plugin_handle_device_vma)

static int init_dumper_args(struct kfd_ioctl_criu_dumper_args *args, __u32 type, __u64 index_start, __u64 num_objects,
			    __u64 objects_size)
{
	memset(args, 0, sizeof(*args));

	args->type = type;
	/* Partial object lists not supported for now so index_start should always be 0 */
	args->objects_index_start = index_start;

	args->num_objects = num_objects;
	args->objects_size = objects_size;

	args->objects = (uintptr_t)xzalloc(args->objects_size);
	if (!args->objects)
		return -ENOMEM;

	return 0;
}

static int init_restorer_args(struct kfd_ioctl_criu_restorer_args *args, __u32 type, __u64 index_start,
			      __u64 num_objects, __u64 objects_size)
{
	memset(args, 0, sizeof(*args));

	args->type = type;
	/* Partial object lists not supported for now so index_start should always be 0 */
	args->objects_index_start = index_start;

	args->num_objects = num_objects;
	args->objects_size = objects_size;

	args->objects = (uintptr_t)xzalloc(args->objects_size);
	if (!args->objects)
		return -ENOMEM;

	return 0;
}

static int pause_process(int fd, const bool enable)
{
	int ret = 0;
	struct kfd_ioctl_criu_pause_args args = { 0 };

	args.pause = enable ? 1 : 0;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_PAUSE, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call pause ioctl");
		goto exit;
	}

exit:
	pr_info("Process %s %s (ret:%d)\n", enable ? "pause" : "unpause", ret ? "Failed" : "Ok", ret);

	return ret;
}

static int dump_process(int fd, struct kfd_ioctl_criu_process_info_args *info_args, CriuKfd *e)
{
	struct kfd_criu_process_bucket *process_bucket;
	struct kfd_ioctl_criu_dumper_args args;
	uint8_t *priv_data;
	int ret = 0;

	pr_debug("Dump process\n");

	ret = init_dumper_args(&args, KFD_CRIU_OBJECT_TYPE_PROCESS, 0, 1,
			       sizeof(*process_bucket) + info_args->process_priv_data_size);

	if (ret)
		goto exit;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call dumper (process) ioctl");
		goto exit;
	}

	ret = allocate_process_entry(e);
	if (ret)
		goto exit;

	process_bucket = (struct kfd_criu_process_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(process_bucket + args.num_objects);

	e->process_entry->private_data.len = process_bucket->priv_data_size;
	e->process_entry->private_data.data = xmalloc(e->process_entry->private_data.len);
	if (!e->process_entry->private_data.data) {
		ret = -ENOMEM;
		goto exit;
	}

	memcpy(e->process_entry->private_data.data, priv_data + process_bucket->priv_data_offset,
	       e->process_entry->private_data.len);
exit:
	xfree((void *)args.objects);
	pr_info("Dumped process %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int dump_devices(int fd, struct kfd_ioctl_criu_process_info_args *info_args, CriuKfd *e)
{
	struct kfd_criu_device_bucket *device_buckets;
	struct kfd_ioctl_criu_dumper_args args;
	uint8_t *priv_data;
	int ret = 0, i;

	pr_debug("Dumping %d devices\n", info_args->total_devices);

	ret = init_dumper_args(&args, KFD_CRIU_OBJECT_TYPE_DEVICE, 0, info_args->total_devices,
			       (info_args->total_devices * sizeof(*device_buckets)) +
				       info_args->devices_priv_data_size);
	if (ret)
		goto exit;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call dumper (devices) ioctl");
		goto exit;
	}

	device_buckets = (struct kfd_criu_device_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(device_buckets + args.num_objects);

	/* When checkpointing on a node where there was already a checkpoint-restore before, the
	 * user_gpu_id and actual_gpu_id will be different.
	 *
	 * We store the user_gpu_id in the stored image files so that the stored images always have
	 * the gpu_id's of the node where the application was first launched.
	 */
	for (int i = 0; i < args.num_objects; i++)
		maps_add_gpu_entry(&checkpoint_maps, device_buckets[i].actual_gpu_id, device_buckets[i].user_gpu_id);

	e->num_of_gpus = info_args->total_devices;
	e->num_of_cpus = src_topology.num_nodes - info_args->total_devices;

	/* The ioctl will only return entries for GPUs, but we also store entries for CPUs and the
	 * information for CPUs is obtained from parsing system topology
	 */
	ret = allocate_device_entries(e, src_topology.num_nodes);
	if (ret) {
		ret = -ENOMEM;
		goto exit;
	}

	pr_debug("Number of CPUs:%d GPUs:%d\n", e->num_of_cpus, e->num_of_gpus);

	/* Store topology information that was obtained from parsing /sys/class/kfd/kfd/topology/ */
	ret = topology_to_devinfo(&src_topology, &checkpoint_maps, e->device_entries);
	if (ret)
		goto exit;

	/* Add private data obtained from IOCTL for each GPU */
	for (i = 0; i < args.num_objects; i++) {
		int j;
		struct kfd_criu_device_bucket *device_bucket = &device_buckets[i];
		pr_debug("Device[%d] user_gpu_id:%x actual_gpu_id:%x\n", i, device_bucket->user_gpu_id,
			 device_bucket->actual_gpu_id);

		for (j = 0; j < src_topology.num_nodes; j++) {
			DeviceEntry *devinfo = e->device_entries[j];

			if (device_bucket->user_gpu_id != devinfo->gpu_id)
				continue;

			devinfo->private_data.len = device_bucket->priv_data_size;
			devinfo->private_data.data = xmalloc(devinfo->private_data.len);

			if (!devinfo->private_data.data) {
				ret = -ENOMEM;
				goto exit;
			}

			memcpy(devinfo->private_data.data, priv_data + device_bucket->priv_data_offset,
			       devinfo->private_data.len);
		}
	}
exit:
	xfree((void *)args.objects);
	pr_info("Dumped devices %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int dump_bos(int fd, struct kfd_ioctl_criu_process_info_args *info_args, CriuKfd *e)
{
	struct kfd_ioctl_criu_dumper_args args = { 0 };
	struct kfd_criu_bo_bucket *bo_buckets;
	uint8_t *priv_data;
	int ret = 0, i;
	char *fname;

	pr_debug("Dumping %lld BOs\n", info_args->total_bos);

	ret = init_dumper_args(&args, KFD_CRIU_OBJECT_TYPE_BO, 0, info_args->total_bos,
			       (info_args->total_bos * sizeof(*bo_buckets)) + info_args->bos_priv_data_size);

	if (ret)
		goto exit;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call dumper (bos) ioctl");
		goto exit;
	}

	bo_buckets = (struct kfd_criu_bo_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(bo_buckets + args.num_objects);

	e->num_of_bos = info_args->total_bos;
	ret = allocate_bo_entries(e, e->num_of_bos, bo_buckets);
	if (ret) {
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < args.num_objects; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		BoEntry *boinfo = e->bo_entries[i];

		boinfo->private_data.len = bo_bucket->priv_data_size;
		boinfo->private_data.data = xmalloc(boinfo->private_data.len);

		if (!boinfo->private_data.data) {
			ret = -ENOMEM;
			goto exit;
		}
		memcpy(boinfo->private_data.data, priv_data + bo_bucket->priv_data_offset, boinfo->private_data.len);

		plugin_log_msg("BO [%d] gpu_id:%x addr:%llx size:%llx offset:%llx dmabuf_fd:%d\n", i, bo_bucket->gpu_id,
			       bo_bucket->addr, bo_bucket->size, bo_bucket->offset, bo_bucket->dmabuf_fd);

		boinfo->gpu_id = maps_get_dest_gpu(&checkpoint_maps, bo_bucket->gpu_id);
		if (!boinfo->gpu_id) {
			ret = -ENODEV;
			goto exit;
		}
		boinfo->addr = bo_bucket->addr;
		boinfo->size = bo_bucket->size;
		boinfo->offset = bo_bucket->offset;
		boinfo->alloc_flags = bo_bucket->alloc_flags;

		if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC) {
				int drm_fd;
				void *addr;
				struct tp_node *tp_node;

				plugin_log_msg("amdgpu_plugin: large bar read possible\n");

				tp_node = sys_get_node_by_gpu_id(&src_topology, boinfo->gpu_id);
				if (!tp_node) {
					ret = -ENODEV;
					goto exit;
				}

				drm_fd = node_get_drm_render_device(tp_node);

				addr = mmap(NULL, boinfo->size, PROT_READ, MAP_SHARED, drm_fd, boinfo->offset);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					ret = -errno;
					goto exit;
				}

				/* direct memcpy is possible on large bars */
				memcpy(boinfo->rawdata.data, addr, boinfo->size);
				munmap(addr, boinfo->size);
			} else {
				size_t bo_size;
				int mem_fd;

				plugin_log_msg("Now try reading BO contents with /proc/pid/mem\n");
				if (asprintf(&fname, PROCPIDMEM, info_args->task_pid) < 0) {
					pr_perror("failed in asprintf, %s", fname);
					ret = -1;
					goto exit;
				}

				mem_fd = open(fname, O_RDONLY);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d", fname, info_args->task_pid);
					free(fname);
					close(mem_fd);
					ret = -1;
					goto exit;
				}

				pr_info("Opened %s file for pid = %d\n", fname, info_args->task_pid);
				free(fname);

				if (lseek(mem_fd, (off_t)bo_bucket->addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d", info_args->task_pid);
					close(mem_fd);
					ret = -1;
					goto exit;
				}

				bo_size = read(mem_fd, boinfo->rawdata.data, boinfo->size);
				if (bo_size != boinfo->size) {
					close(mem_fd);
					pr_perror("Can't read buffer");
					ret = -1;
					goto exit;
				}
				close(mem_fd);
			}
		}
	}
exit:
	xfree((void *)args.objects);
	pr_info("Dumped bos %s (ret:%d)\n", ret ? "failed" : "ok", ret);
	return ret;
}

static int dump_queues(int fd, struct kfd_ioctl_criu_process_info_args *info_args, CriuKfd *e)
{
	struct kfd_ioctl_criu_dumper_args args = { 0 };
	struct kfd_criu_queue_bucket *queue_buckets;
	uint8_t *priv_data;
	int ret = 0, i;

	pr_debug("Dumping %d queues\n", info_args->total_queues);

	if (!info_args->total_queues)
		return 0;

	ret = init_dumper_args(&args, KFD_CRIU_OBJECT_TYPE_QUEUE, 0, info_args->total_queues,
			       (info_args->total_queues * sizeof(*queue_buckets)) + info_args->queues_priv_data_size);

	if (ret)
		goto exit;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call dumper (queues) ioctl");
		goto exit;
	}

	queue_buckets = (struct kfd_criu_queue_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(queue_buckets + args.num_objects);

	e->num_of_queues = info_args->total_queues;
	ret = allocate_q_entries(e, e->num_of_queues);
	if (ret) {
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < args.num_objects; i++) {
		struct kfd_criu_queue_bucket *q_bucket = &queue_buckets[i];
		QEntry *qinfo = e->q_entries[i];

		pr_debug("Queue [%d] gpu_id:%x\n", i, q_bucket->gpu_id);

		qinfo->gpu_id = maps_get_dest_gpu(&checkpoint_maps, q_bucket->gpu_id);
		if (!qinfo->gpu_id) {
			ret = -ENODEV;
			goto exit;
		}

		qinfo->private_data.len = q_bucket->priv_data_size;
		qinfo->private_data.data = xmalloc(qinfo->private_data.len);

		if (!qinfo->private_data.data) {
			ret = -ENOMEM;
			goto exit;
		}
		memcpy(qinfo->private_data.data, priv_data + q_bucket->priv_data_offset, qinfo->private_data.len);
	}
exit:
	xfree((void *)args.objects);
	pr_info("Dumped queues %s (ret:%d)\n", ret ? "failed" : "ok", ret);
	return ret;
}

static int dump_events(int fd, struct kfd_ioctl_criu_process_info_args *info_args, CriuKfd *e)
{
	int ret = 0, i;
	struct kfd_ioctl_criu_dumper_args args = { 0 };
	struct kfd_criu_event_bucket *ev_buckets;
	uint8_t *priv_data;

	pr_debug("Dumping %d events\n", info_args->total_events);

	if (!info_args->total_events)
		return 0;

	ret = init_dumper_args(&args, KFD_CRIU_OBJECT_TYPE_EVENT, 0, info_args->total_events,
			       (info_args->total_events * sizeof(*ev_buckets)) + info_args->events_priv_data_size);

	if (ret)
		goto exit;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call dumper (events) ioctl");
		goto exit;
	}

	ev_buckets = (struct kfd_criu_event_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(ev_buckets + args.num_objects);

	e->num_of_events = info_args->total_events;

	ret = allocate_ev_entries(e, e->num_of_events);
	if (ret) {
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < args.num_objects; i++) {
		struct kfd_criu_event_bucket *ev_bucket = &ev_buckets[i];
		EvEntry *evinfo = e->ev_entries[i];

		pr_debug("Event[%d] gpu_id:%x\n", i, ev_bucket->gpu_id);

		if (ev_bucket->gpu_id) {
			evinfo->gpu_id = maps_get_dest_gpu(&checkpoint_maps, ev_bucket->gpu_id);
			if (!evinfo->gpu_id) {
				ret = -ENODEV;
				goto exit;
			}
		}

		evinfo->private_data.len = ev_bucket->priv_data_size;
		evinfo->private_data.data = xmalloc(evinfo->private_data.len);
		if (!evinfo->private_data.data) {
			ret = -ENOMEM;
			goto exit;
		}

		memcpy(evinfo->private_data.data, priv_data + ev_bucket->priv_data_offset, evinfo->private_data.len);
	}
exit:
	xfree((void *)args.objects);
	pr_info("Dumped events %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

int amdgpu_plugin_dump_file(int fd, int id)
{
	struct kfd_ioctl_criu_process_info_args info_args = { 0 };
	char img_path[PATH_MAX];
	struct stat st, st_kfd;
	unsigned char *buf;
	CriuKfd *e = NULL;
	int ret = 0;
	size_t len;

	if (fstat(fd, &st) == -1) {
		pr_perror("amdgpu_plugin: fstat error");
		return -1;
	}

	ret = stat(AMDGPU_KFD_DEVICE, &st_kfd);
	if (ret == -1) {
		pr_perror("amdgpu_plugin: fstat error for /dev/kfd");
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

	/* Check whether this plugin was called for kfd or render nodes */
	if (major(st.st_rdev) != major(st_kfd.st_rdev) || minor(st.st_rdev) != 0) {
		/* This is RenderD dumper plugin, save the render minor and gpu_id */

		CriuRenderNode rd = CRIU_RENDER_NODE__INIT;
		struct tp_node *tp_node;

		pr_info("amdgpu_plugin: Dumper called for /dev/dri/renderD%d, FD = %d, ID = %d\n", minor(st.st_rdev),
			fd, id);

		tp_node = sys_get_node_by_render_minor(&src_topology, minor(st.st_rdev));
		if (!tp_node) {
			pr_err("amdgpu_plugin: Failed to find a device with minor number = %d\n", minor(st.st_rdev));

			return -ENODEV;
		}

		rd.gpu_id = maps_get_dest_gpu(&checkpoint_maps, tp_node->gpu_id);
		if (!rd.gpu_id)
			return -ENODEV;

		len = criu_render_node__get_packed_size(&rd);
		buf = xmalloc(len);
		if (!buf)
			return -ENOMEM;

		criu_render_node__pack(&rd, buf);

		snprintf(img_path, sizeof(img_path), "renderDXXX.%d.img", id);
		ret = write_file(img_path, buf, len);
		if (ret) {
			xfree(buf);
			return ret;
		}

		/* Need to return success here so that criu can call plugins for renderD nodes */
		xfree(buf);
		return ret;
	}

	pr_info("amdgpu_plugin: %s : %s() called for fd = %d\n", CR_PLUGIN_DESC.name, __func__, major(st.st_rdev));

	/* Evict all queues */
	ret = pause_process(fd, true);
	if (ret)
		goto exit;

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_PROCESS_INFO, &info_args) == -1) {
		pr_perror("amdgpu_plugin: Failed to call process info ioctl");
		return -1;
	}

	pr_info("amdgpu_plugin: devices:%d bos:%lld queues:%d events:%d svm-range:%lld\n", info_args.total_devices,
		info_args.total_bos, info_args.total_queues, info_args.total_events, info_args.total_svm_ranges);

	e = xmalloc(sizeof(*e));
	if (!e) {
		pr_err("Failed to allocate proto structure\n");
		return -ENOMEM;
	}

	criu_kfd__init(e);
	e->pid = info_args.task_pid;

	ret = dump_process(fd, &info_args, e);
	if (ret)
		goto exit;

	ret = dump_devices(fd, &info_args, e);
	if (ret)
		goto exit;

	ret = dump_bos(fd, &info_args, e);
	if (ret)
		goto exit;

	ret = dump_queues(fd, &info_args, e);
	if (ret)
		goto exit;

	ret = dump_events(fd, &info_args, e);
	if (ret)
		goto exit;

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);
	pr_info("amdgpu_plugin: img_path = %s\n", img_path);

	len = criu_kfd__get_packed_size(e);

	pr_info("amdgpu_plugin: Len = %ld\n", len);

	buf = xmalloc(len);
	if (!buf) {
		pr_perror("Failed to allocate memory to store protobuf");
		ret = -ENOMEM;
		goto exit;
	}

	criu_kfd__pack(e, buf);

	ret = write_file(img_path, buf, len);

	xfree(buf);
exit:
	/* Restore all queues */
	pause_process(fd, false);

	sys_close_drm_render_devices(&src_topology);
	free_e(e);

	if (ret)
		pr_err("amdgpu_plugin: Failed to dump (ret:%d)\n", ret);
	else
		pr_info("amdgpu_plugin: Dump successful\n");

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, amdgpu_plugin_dump_file)

static int restore_process(int fd, CriuKfd *e)
{
	struct kfd_criu_process_bucket *process_bucket;
	struct kfd_ioctl_criu_restorer_args args;
	uint8_t *priv_data;
	int ret = 0;

	pr_debug("Restore process\n");

	ret = init_restorer_args(&args, KFD_CRIU_OBJECT_TYPE_PROCESS, 0, 1,
				 sizeof(*process_bucket) + e->process_entry->private_data.len);

	if (ret)
		goto exit;

	process_bucket = (struct kfd_criu_process_bucket *)args.objects;
	/* First private data starts after all buckets */
	priv_data = (void *)(process_bucket + args.num_objects);

	process_bucket->priv_data_offset = 0;
	process_bucket->priv_data_size = e->process_entry->private_data.len;

	memcpy(priv_data, e->process_entry->private_data.data, e->process_entry->private_data.len);

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call restorer (process) ioctl");
		goto exit;
	}

exit:
	pr_info("Restore process %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

/* Restore per-device information */
static int restore_devices(int fd, CriuKfd *e)
{
	struct kfd_ioctl_criu_restorer_args args = { 0 };
	struct kfd_criu_device_bucket *device_buckets;
	int ret = 0, bucket_index = 0;
	uint64_t priv_data_offset = 0;
	uint64_t objects_size = 0;
	uint8_t *priv_data;

	pr_debug("Restoring %d devices\n", e->num_of_gpus);

	for (int i = 0; i < e->num_of_cpus + e->num_of_gpus; i++) {
		/* Skip CPUs */
		if (!e->device_entries[i]->gpu_id)
			continue;

		objects_size += sizeof(*device_buckets) + e->device_entries[i]->private_data.len;
	}

	ret = init_restorer_args(&args, KFD_CRIU_OBJECT_TYPE_DEVICE, 0, e->num_of_gpus, objects_size);
	if (ret)
		goto exit;

	device_buckets = (struct kfd_criu_device_bucket *)args.objects;
	priv_data = (void *)(device_buckets + args.num_objects);

	for (int entries_i = 0; entries_i < e->num_of_cpus + e->num_of_gpus; entries_i++) {
		struct kfd_criu_device_bucket *device_bucket;
		DeviceEntry *devinfo = e->device_entries[entries_i];
		struct tp_node *tp_node;

		if (!devinfo->gpu_id)
			continue;

		device_bucket = &device_buckets[bucket_index++];

		device_bucket->priv_data_size = devinfo->private_data.len;
		device_bucket->priv_data_offset = priv_data_offset;

		priv_data_offset += device_bucket->priv_data_size;

		memcpy(priv_data + device_bucket->priv_data_offset, devinfo->private_data.data,
		       device_bucket->priv_data_size);

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
			pr_perror("amdgpu_plugin: Can't pass NULL drm render fd to driver");
			fd = -EBADFD;
			goto exit;
		} else {
			pr_info("amdgpu_plugin: passing drm render fd = %d to driver\n", device_bucket->drm_fd);
		}
	}

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call restorer (devices) ioctl");
		goto exit;
	}
exit:

	xfree((void *)args.objects);
	pr_info("Restore devices %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int restore_bos(int fd, CriuKfd *e)
{
	struct kfd_ioctl_criu_restorer_args args = { 0 };
	struct kfd_criu_bo_bucket *bo_buckets;
	uint64_t priv_data_offset = 0;
	uint64_t objects_size = 0;
	uint8_t *priv_data;
	int ret = 0;
	char *fname;
	void *addr;

	pr_debug("Restoring %ld BOs\n", e->num_of_bos);

	for (int i = 0; i < e->num_of_bos; i++)
		objects_size += sizeof(*bo_buckets) + e->bo_entries[i]->private_data.len;

	ret = init_restorer_args(&args, KFD_CRIU_OBJECT_TYPE_BO, 0, e->num_of_bos, objects_size);
	if (ret)
		goto exit;

	bo_buckets = (struct kfd_criu_bo_bucket *)args.objects;
	priv_data = (void *)(bo_buckets + args.num_objects);

	for (int i = 0; i < args.num_objects; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		BoEntry *bo_entry = e->bo_entries[i];

		bo_bucket->priv_data_size = bo_entry->private_data.len;
		bo_bucket->priv_data_offset = priv_data_offset;
		priv_data_offset += bo_bucket->priv_data_size;

		memcpy(priv_data + bo_bucket->priv_data_offset, bo_entry->private_data.data, bo_bucket->priv_data_size);

		bo_bucket->gpu_id = maps_get_dest_gpu(&restore_maps, bo_entry->gpu_id);
		if (!bo_bucket->gpu_id) {
			ret = -ENODEV;
			goto exit;
		}

		bo_bucket->addr = bo_entry->addr;
		bo_bucket->size = bo_entry->size;
		bo_bucket->offset = bo_entry->offset;
		bo_bucket->alloc_flags = bo_entry->alloc_flags;

		plugin_log_msg("BO [%d] gpu_id:%x addr:%llx size:%llx offset:%llx\n", i, bo_bucket->gpu_id,
			       bo_bucket->addr, bo_bucket->size, bo_bucket->offset);
	}

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call restorer (bos) ioctl");
		goto exit;
	}

	for (int i = 0; i < args.num_objects; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		BoEntry *bo_entry = e->bo_entries[i];

		struct tp_node *tp_node;

		if (bo_bucket->alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT |
					      KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP | KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL)) {
			struct vma_metadata *vma_md;

			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md) {
				ret = -ENOMEM;
				goto exit;
			}

			memset(vma_md, 0, sizeof(*vma_md));

			vma_md->old_pgoff = bo_bucket->offset;
			vma_md->vma_entry = bo_bucket->addr;

			tp_node = sys_get_node_by_gpu_id(&dest_topology, bo_bucket->gpu_id);
			if (!tp_node) {
				pr_err("Failed to find node with gpu_id:0x%04x\n", bo_bucket->gpu_id);
				ret = -ENODEV;
				goto exit;
			}

			vma_md->new_minor = tp_node->drm_render_minor;
			vma_md->new_pgoff = bo_bucket->restored_offset;
			vma_md->fd = node_get_drm_render_device(tp_node);

			plugin_log_msg("amdgpu_plugin: adding vma_entry:addr:0x%lx old-off:0x%lx "
				       "new_off:0x%lx new_minor:%d\n",
				       vma_md->vma_entry, vma_md->old_pgoff, vma_md->new_pgoff, vma_md->new_minor);

			list_add_tail(&vma_md->list, &update_vma_info_list);
		}

		if (bo_bucket->alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {
			int drm_fd = node_get_drm_render_device(tp_node);

			plugin_log_msg("amdgpu_plugin: Trying mmap in stage 2\n");
			if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC ||
			    bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
				plugin_log_msg("amdgpu_plugin: large bar write possible\n");
				addr = mmap(NULL, bo_bucket->size, PROT_WRITE, MAP_SHARED, drm_fd,
					    bo_bucket->restored_offset);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed");
					fd = -EBADFD;
					goto exit;
				}

				/* direct memcpy is possible on large bars */
				memcpy(addr, (void *)bo_entry->rawdata.data, bo_entry->size);
				munmap(addr, bo_entry->size);
			} else {
				size_t bo_size;
				int mem_fd;
				/* Use indirect host data path via /proc/pid/mem
				 * on small pci bar GPUs or for Buffer Objects
				 * that don't have HostAccess permissions.
				 */
				plugin_log_msg("amdgpu_plugin: using PROCPIDMEM to restore BO contents\n");
				addr = mmap(NULL, bo_bucket->size, PROT_NONE, MAP_SHARED, drm_fd,
					    bo_bucket->restored_offset);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed");
					fd = -EBADFD;
					goto exit;
				}

				if (asprintf(&fname, PROCPIDMEM, e->pid) < 0) {
					pr_perror("failed in asprintf, %s", fname);
					munmap(addr, bo_bucket->size);
					fd = -EBADFD;
					goto exit;
				}

				mem_fd = open(fname, O_RDWR);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d", fname, e->pid);
					free(fname);
					munmap(addr, bo_bucket->size);
					fd = -EBADFD;
					goto exit;
				}

				plugin_log_msg("Opened %s file for pid = %d", fname, e->pid);
				free(fname);

				if (lseek(mem_fd, (off_t)addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d", e->pid);
					munmap(addr, bo_entry->size);
					fd = -EBADFD;
					goto exit;
				}

				plugin_log_msg("Attempt writing now");
				bo_size = write(mem_fd, bo_entry->rawdata.data, bo_entry->size);
				if (bo_size != bo_entry->size) {
					pr_perror("Can't write buffer");
					munmap(addr, bo_entry->size);
					fd = -EBADFD;
					goto exit;
				}
				munmap(addr, bo_entry->size);
				close(mem_fd);
			}
		} else {
			plugin_log_msg("Not a VRAM BO\n");
			continue;
		}
	}

exit:
	xfree((void *)args.objects);
	pr_info("Restore BOs %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int restore_queues(int fd, CriuKfd *e)
{
	struct kfd_ioctl_criu_restorer_args args = { 0 };
	struct kfd_criu_queue_bucket *q_buckets;
	uint64_t priv_data_offset = 0;
	uint64_t objects_size = 0;
	uint8_t *priv_data;
	int ret = 0;

	if (!e->num_of_queues)
		return 0;

	pr_debug("Restoring %d queues\n", e->num_of_queues);

	for (int i = 0; i < e->num_of_queues; i++)
		objects_size += sizeof(*q_buckets) + e->q_entries[i]->private_data.len;

	ret = init_restorer_args(&args, KFD_CRIU_OBJECT_TYPE_QUEUE, 0, e->num_of_queues, objects_size);
	if (ret)
		goto exit;

	q_buckets = (struct kfd_criu_queue_bucket *)args.objects;
	priv_data = (void *)(q_buckets + args.num_objects);

	for (int i = 0; i < args.num_objects; i++) {
		struct kfd_criu_queue_bucket *q_bucket = &q_buckets[i];
		QEntry *qinfo = e->q_entries[i];

		q_bucket->priv_data_size = qinfo->private_data.len;
		q_bucket->priv_data_offset = priv_data_offset;
		priv_data_offset += q_bucket->priv_data_size;

		memcpy(priv_data + q_bucket->priv_data_offset, qinfo->private_data.data, q_bucket->priv_data_size);

		q_bucket->gpu_id = maps_get_dest_gpu(&restore_maps, qinfo->gpu_id);
		if (!q_bucket->gpu_id) {
			ret = -ENODEV;
			goto exit;
		}

		pr_debug("Queue [%d] gpu_id:%x\n", i, q_bucket->gpu_id);
	}

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call restorer (queues) ioctl");
		goto exit;
	}

exit:
	xfree((void *)args.objects);
	pr_info("Restore queues %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

static int restore_events(int fd, CriuKfd *e)
{
	struct kfd_ioctl_criu_restorer_args args = { 0 };
	struct kfd_criu_event_bucket *ev_buckets;
	uint64_t priv_data_offset = 0;
	uint64_t objects_size = 0;
	uint8_t *priv_data;
	int ret = 0;

	if (!e->num_of_events)
		return 0;

	pr_debug("Restoring %d events\n", e->num_of_events);

	for (int i = 0; i < e->num_of_events; i++)
		objects_size += sizeof(*ev_buckets) + e->ev_entries[i]->private_data.len;

	ret = init_restorer_args(&args, KFD_CRIU_OBJECT_TYPE_EVENT, 0, e->num_of_events, objects_size);
	if (ret)
		goto exit;

	ev_buckets = (struct kfd_criu_event_bucket *)args.objects;
	priv_data = (void *)(ev_buckets + args.num_objects);

	for (int i = 0; i < args.num_objects; i++) {
		struct kfd_criu_event_bucket *ev_bucket = &ev_buckets[i];
		EvEntry *evinfo = e->ev_entries[i];

		ev_bucket->priv_data_size = evinfo->private_data.len;
		ev_bucket->priv_data_offset = priv_data_offset;
		priv_data_offset += ev_bucket->priv_data_size;

		memcpy(priv_data + ev_bucket->priv_data_offset, evinfo->private_data.data, ev_bucket->priv_data_size);

		if (evinfo->gpu_id) {
			ev_bucket->gpu_id = maps_get_dest_gpu(&restore_maps, evinfo->gpu_id);
			if (!ev_bucket->gpu_id) {
				ret = -ENODEV;
				goto exit;
			}
		}

		plugin_log_msg("Event [%d] gpu_id:%x\n", i, ev_bucket->gpu_id);
	}

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to call restorer (events) ioctl");
		goto exit;
	}

exit:
	xfree((void *)args.objects);
	pr_info("Restore events %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);
	return ret;
}

int amdgpu_plugin_restore_file(int id)
{
	int ret = 0, fd;
	char img_path[PATH_MAX];
	struct stat filestat;
	unsigned char *buf;
	CriuRenderNode *rd;
	CriuKfd *e = NULL;

	pr_info("amdgpu_plugin: Initialized kfd plugin restorer with ID = %d\n", id);

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);

	if (stat(img_path, &filestat) == -1) {
		struct tp_node *tp_node;
		uint32_t target_gpu_id;

		pr_perror("open(%s)", img_path);
		/* This is restorer plugin for renderD nodes. Criu doesn't guarantee that they will
		 * be called before the plugin is called for kfd file descriptor.
		 * TODO: Currently, this code will only work if this function is called for /dev/kfd
		 * first as we assume restore_maps is already filled. Need to fix this later.
		 */
		snprintf(img_path, sizeof(img_path), "renderDXXX.%d.img", id);

		if (stat(img_path, &filestat) == -1) {
			pr_perror("Failed to read file stats");
			return -1;
		}
		pr_info("renderD file size on disk = %ld\n", filestat.st_size);

		buf = xmalloc(filestat.st_size);
		if (!buf) {
			pr_perror("Failed to allocate memory");
			return -ENOMEM;
		}

		if (read_file(img_path, buf, filestat.st_size)) {
			pr_perror("Unable to read from %s", img_path);
			xfree(buf);
			return -1;
		}

		rd = criu_render_node__unpack(NULL, filestat.st_size, buf);
		if (rd == NULL) {
			pr_perror("Unable to parse the KFD message %d", id);
			xfree(buf);
			return -1;
		}

		pr_info("amdgpu_plugin: render node gpu_id = 0x%04x\n", rd->gpu_id);

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

		pr_info("amdgpu_plugin: render node destination gpu_id = 0x%04x\n", tp_node->gpu_id);

		fd = node_get_drm_render_device(tp_node);
		if (fd < 0)
			pr_err("amdgpu_plugin: Failed to open render device (minor:%d)\n", tp_node->drm_render_minor);
	fail:
		criu_render_node__free_unpacked(rd, NULL);
		xfree(buf);
		return fd;
	}

	fd = open(AMDGPU_KFD_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	pr_info("amdgpu_plugin: Opened kfd, fd = %d\n", fd);

	pr_info("kfd img file size on disk = %ld\n", filestat.st_size);

	buf = xmalloc(filestat.st_size);
	if (!buf) {
		pr_perror("Failed to allocate memory");
		return -ENOMEM;
	}

	if (read_file(img_path, buf, filestat.st_size)) {
		pr_perror("Unable to read from %s", img_path);
		xfree(buf);
		return -1;
	}
	e = criu_kfd__unpack(NULL, filestat.st_size, buf);
	if (e == NULL) {
		pr_err("Unable to parse the KFD message %#x\n", id);
		xfree(buf);
		return -1;
	}

	plugin_log_msg("amdgpu_plugin: read image file data\n");

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

	ret = restore_process(fd, e);
	if (ret)
		goto exit;

	ret = restore_devices(fd, e);
	if (ret)
		goto exit;

	ret = restore_bos(fd, e);
	if (ret)
		goto exit;

	ret = restore_queues(fd, e);
	if (ret)
		goto exit;

	ret = restore_events(fd, e);
	if (ret)
		goto exit;

exit:
	sys_close_drm_render_devices(&dest_topology);

	if (e)
		criu_kfd__free_unpacked(e, NULL);

	if (ret) {
		pr_err("amdgpu_plugin: Failed to restore (ret:%d)\n", ret);
		fd = ret;
	} else {
		pr_info("amdgpu_plugin: Restore successful (fd:%d)\n", fd);
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

	plugin_log_msg("amdgpu_plugin: Enter %s\n", __func__);

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

			if (is_renderD)
				*updated_fd = vma_md->fd;
			else
				*updated_fd = -1;

			plugin_log_msg("amdgpu_plugin: old_pgoff=0x%lx new_pgoff=0x%lx fd=%d\n", vma_md->old_pgoff,
				       vma_md->new_pgoff, *updated_fd);

			return 1;
		}
	}
	pr_info("No match for addr:0x%lx offset:%lx\n", addr, old_offset);
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, amdgpu_plugin_update_vmamap)

int amdgpu_plugin_resume_devices_late(int target_pid)
{
	struct kfd_ioctl_criu_resume_args args = { 0 };
	int fd, ret = 0;

	pr_info("amdgpu_plugin: Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open(AMDGPU_KFD_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	args.pid = target_pid;
	pr_info("amdgpu_plugin: Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESUME, &args) == -1) {
		pr_perror("restore late ioctl failed");
		ret = -1;
	}

	close(fd);
	return ret;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, amdgpu_plugin_resume_devices_late)
