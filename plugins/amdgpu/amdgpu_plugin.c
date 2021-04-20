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
#include "criu-amdgpu.pb-c.h"

#include "kfd_ioctl.h"
#include "xmalloc.h"
#include "criu-log.h"

#include "common/list.h"
#include "amdgpu_plugin_topology.h"

#define DRM_FIRST_RENDER_NODE 128
#define DRM_LAST_RENDER_NODE 255

#define PROCPIDMEM      "/proc/%d/mem"

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
#define plugin_log_msg(fmt, ...) {}
#endif

struct vma_metadata {
	struct list_head list;
	uint64_t old_pgoff;
	uint64_t new_pgoff;
	uint64_t vma_entry;
	uint32_t new_minor;
};

static LIST_HEAD(update_vma_info_list);

int open_drm_render_device(int minor)
{
	char path[128];
	int fd;

	if (minor < DRM_FIRST_RENDER_NODE || minor > DRM_LAST_RENDER_NODE) {
		pr_perror("DRM render minor %d out of range [%d, %d]\n", minor,
			  DRM_FIRST_RENDER_NODE, DRM_LAST_RENDER_NODE);
		return -EINVAL;
	}

	sprintf(path, "/dev/dri/renderD%d", minor);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT && errno != EPERM) {
			pr_err("Failed to open %s: %s\n", path, strerror(errno));
			if (errno == EACCES)
				pr_err("Check user is in \"video\" group\n");
		}
		return -EBADFD;
	}

	return fd;
}

int write_file(const char *file_path, const void *buf, const size_t buf_len)
{
	int fd;
	FILE *fp;
	size_t len_wrote;

	fd = openat(criu_get_image_dir(), file_path, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		pr_perror("Cannot open %s", file_path);
		return -EPERM;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		pr_perror("Cannot fdopen %s", file_path);
		return -EPERM;
	}

	len_wrote = fwrite(buf, 1, buf_len, fp);
	if (len_wrote != buf_len) {
		pr_perror("Unable to write %s (wrote:%ld buf_len:%ld)\n", file_path, len_wrote, buf_len);
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
		return -ENOENT;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		pr_perror("Cannot fdopen %s", file_path);
		return -EPERM;
	}

	len_read = fread(buf, 1, buf_len, fp);
	if (len_read != buf_len) {
		pr_perror("Unable to read %s\n", file_path);
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
		pr_perror("KFD file descriptor not valid in this process\n");
	return ret;
}

static void free_e(CriuKfd *e)
{
	for (int i = 0; i < e->n_bo_info_test; i++) {
		if (e->bo_info_test[i]->bo_rawdata.data)
			xfree(e->bo_info_test[i]->bo_rawdata.data);
		if (e->bo_info_test[i])
			xfree(e->bo_info_test[i]);
	}
	for (int i = 0; i < e->n_devinfo_entries; i++) {
		if (e->devinfo_entries[i]) {
			for (int j = 0; j < e->devinfo_entries[i]->n_iolinks; j++)
				xfree(e->devinfo_entries[i]->iolinks[j]);

			xfree(e->devinfo_entries[i]);
		}
	}
	for (int i = 0; i < e->n_q_entries; i++) {
		if (e->q_entries[i])
			xfree(e->q_entries[i]);
	}
	for (int i = 0; i < e->n_ev_entries; i++) {
		if (e->ev_entries[i])
			xfree(e->ev_entries[i]);
	}
	xfree(e);
}

static int allocate_devinfo_entries(CriuKfd *e, int num_of_devices)
{
	e->devinfo_entries = xmalloc(sizeof(DevinfoEntry*) * num_of_devices);
	if (!e->devinfo_entries) {
		pr_err("Failed to allocate devinfo_entries\n");
		return -1;
	}

	for (int i = 0; i < num_of_devices; i++)
	{
		DevinfoEntry *entry = xmalloc(sizeof(DevinfoEntry));
		if (!entry) {
			pr_err("Failed to allocate entry\n");
			return -ENOMEM;
		}

		devinfo_entry__init(entry);

		e->devinfo_entries[i] = entry;
		e->n_devinfo_entries++;

	}
	return 0;
}

static int allocate_bo_info_test(CriuKfd *e, int num_bos, struct kfd_criu_bo_buckets *bo_bucket_ptr)
{
	e->bo_info_test = xmalloc(sizeof(BoEntriesTest*) * num_bos);
	if (!e->bo_info_test) {
		pr_err("Failed to allocate bo_info\n");
		return -ENOMEM;
	}

	pr_info("Inside allocate_bo_info_test\n");
	for (int i = 0; i < num_bos; i++)
	{
		BoEntriesTest *botest;
		botest = xmalloc(sizeof(*botest));
		if (!botest) {
			pr_err("Failed to allocate botest\n");
			return -ENOMEM;
		}

		bo_entries_test__init(botest);

		if ((bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    (bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			botest->bo_rawdata.data = xmalloc((bo_bucket_ptr)[i].bo_size);
			botest->bo_rawdata.len = (bo_bucket_ptr)[i].bo_size;
		}

		e->bo_info_test[i] = botest;
		e->n_bo_info_test++;

	}

	return 0;
}

static int allocate_q_entries(CriuKfd *e, int num_queues)
{
	e->q_entries = xmalloc(sizeof(QEntry*) * num_queues);
	if (!e->q_entries) {
		pr_err("Failed to allocate q_entries\n");
		return -1;
	}

	for (int i = 0; i < num_queues; i++) {
		QEntry *q_entry = xmalloc(sizeof(QEntry));
		if (!q_entry) {
			pr_err("Failed to allocate q_entry\n");
			return -ENOMEM;
		}
		q_entry__init(q_entry);

		e->q_entries[i] = q_entry;
		e->n_q_entries++;

	}
	return 0;
}

static int allocate_ev_entries(CriuKfd *e, int num_events)
{
	e->ev_entries = xmalloc(sizeof(EvEntry*) * num_events);
	if (!e->ev_entries) {
		pr_err("Failed to allocate ev_entries\n");
		return -1;
	}

	for (int i = 0; i < num_events; i++) {
		EvEntry *ev_entry = xmalloc(sizeof(EvEntry));
		if (!ev_entry) {
			pr_err("Failed to allocate ev_entry\n");
			return -ENOMEM;
		}
		ev_entry__init(ev_entry);
		e->ev_entries[i] = ev_entry;
		e->n_ev_entries++;

	}
	e->num_of_events = num_events;
	return 0;
}

int topology_to_devinfo(struct tp_system *sys, struct kfd_criu_devinfo_bucket *devinfo_buckets,
			struct device_maps *maps, DevinfoEntry **devinfos)
{
	struct tp_node *node;
	uint32_t devinfo_index = 0;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		DevinfoEntry *devinfo = devinfos[devinfo_index++];

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
			devinfo->iolinks = xmalloc(sizeof(DevIolink*) * node->num_valid_iolinks);
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

int devinfo_to_topology(DevinfoEntry *devinfos[], uint32_t num_devices, struct tp_system *sys)
{
	for (int i = 0; i < num_devices; i++) {
		struct tp_node *node;
		DevinfoEntry *devinfo = devinfos[i];

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
	char *opt_param = NULL;
	pr_info("amdgpu_plugin: initialized:  %s (AMDGPU/KFD)\n",
						CR_PLUGIN_DESC.name);

	topology_init(&src_topology);
	topology_init(&dest_topology);
	maps_init(&checkpoint_maps);
	maps_init(&restore_maps);

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		kfd_gpu_override = NULL;
		kfd_topology_check = true;
		kfd_fw_version_check = true;
		kfd_sdma_fw_version_check = true;
		kfd_caches_count_check = true;
		kfd_num_gws_check = true;
		kfd_vram_size_check = true;
		kfd_ignore_numa = false;

		/* Forces gpu mapping to specific gpu list */
		/* Expected destination gpu format:
		*	KFD_DESTINATION_GPUS=0xff31,0x90db
		*	KFD_DESTINATION_GPUS=65329,37083
		*	KFD_DESTINATION_GPUS=renderD129,renderD128
		*/
		kfd_gpu_override = getenv("KFD_DESTINATION_GPUS");
		pr_info("param: KFD_DESTINATION_GPUS:%s\n", kfd_gpu_override ? kfd_gpu_override : "None");

		if ((opt_param = getenv("KFD_TOPOLOGY_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_topology_check = false;
		}
		pr_info("param: KFD_TOPOLOGY_CHECK:%s\n", kfd_topology_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_FW_VER_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_fw_version_check = false;
		}
		pr_info("param: KFD_FW_VERSION_CHECK:%s\n", kfd_fw_version_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_SDMA_FW_VER_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_sdma_fw_version_check = false;
		}
		pr_info("param: KFD_SDMA_FW_VER_CHECK:%s\n", kfd_sdma_fw_version_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_CACHES_COUNT_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_caches_count_check = false;
		}
		pr_info("param: KFD_CACHES_COUNT_CHECK:%s\n", kfd_caches_count_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_NUM_GWS_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_num_gws_check = false;
		}
		pr_info("param: KFD_NUM_GWS_CHECK:%s\n", kfd_num_gws_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_VRAM_SIZE_CHECK"))) {
			if (!strcmp(opt_param, "0") || !strcmp(opt_param, "NO"))
				kfd_vram_size_check = false;
		}
		pr_info("param: KFD_VRAM_SIZE_CHECK:%s\n", kfd_vram_size_check ? "Y" : "N");

		if ((opt_param = getenv("KFD_IGNORE_NUMA"))) {
			if (!strcmp(opt_param, "1") || !strcmp(opt_param, "Y"))
				kfd_ignore_numa = true;
		}
		pr_info("param: KFD_IGNORE_NUMA:%s\n", kfd_ignore_numa ? "Y" : "N");
	}
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

int amdgpu_plugin_dump_file(int fd, int id)
{
	struct kfd_ioctl_criu_helper_args helper_args = {0};
	struct kfd_criu_devinfo_bucket *devinfo_bucket_ptr;
	struct kfd_ioctl_criu_dumper_args args = {0};
	struct kfd_criu_bo_buckets *bo_bucket_ptr;
	struct kfd_criu_q_bucket *q_bucket_ptr;
	struct kfd_criu_ev_bucket *ev_buckets_ptr = NULL;
	int ret;
	char img_path[PATH_MAX];
	struct stat st, st_kfd;
	unsigned char *buf;
	size_t len;

	pr_debug("amdgpu_plugin: Enter cr_plugin_dump_file()- ID = 0x%x\n", id);
	ret = 0;
	CriuKfd *e;

	if (fstat(fd, &st) == -1) {
		pr_perror("amdgpu_plugin: fstat error");
		return -1;
	}

	ret = stat("/dev/kfd", &st_kfd);
	if (ret == -1) {
		pr_perror("amdgpu_plugin: fstat error for /dev/kfd\n");
		return -1;
	}

	if (topology_parse(&src_topology, "Checkpoint"))
		return -1;

	/* We call topology_determine_iolinks to validate io_links. If io_links are not valid
	   we do not store them inside the checkpointed images */
	if (topology_determine_iolinks(&src_topology)) {
		pr_err("Failed to determine iolinks from topology\n");
		return -1;
	}

	/* Check whether this plugin was called for kfd or render nodes */
	if (major(st.st_rdev) != major(st_kfd.st_rdev) ||
		 minor(st.st_rdev) != 0) {
		/* This is RenderD dumper plugin, save the render minor and gpu_id */
		CriuRenderNode rd = CRIU_RENDER_NODE__INIT;
		struct tp_node *tp_node;

		pr_info("amdgpu_plugin: Dumper called for /dev/dri/renderD%d, FD = %d, ID = %d\n",
			minor(st.st_rdev), fd, id);

		tp_node = sys_get_node_by_render_minor(&src_topology, minor(st.st_rdev));
		if (!tp_node) {
			pr_err("amdgpu_plugin: Failed to find a device with minor number = %d\n",
				minor(st.st_rdev));

			return -EFAULT;
		}

		rd.gpu_id = maps_get_dest_gpu(&checkpoint_maps, tp_node->gpu_id);
		if (!rd.gpu_id) {
			ret = -EFAULT;
			goto failed;
		}

		len = criu_render_node__get_packed_size(&rd);
		buf = xmalloc(len);
		if (!buf)
			return -ENOMEM;

		criu_render_node__pack(&rd, buf);

		snprintf(img_path, sizeof(img_path), "renderDXXX.%d.img", id);
		ret = write_file(img_path,  buf, len);
		if (ret) {
			xfree(buf);
			return ret;
		}

		xfree(buf);

		/* Need to return success here so that criu can call plugins for renderD nodes */
		return ret;
	}

	pr_info("amdgpu_plugin: %s : %s() called for fd = %d\n", CR_PLUGIN_DESC.name,
		  __func__, major(st.st_rdev));

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_HELPER, &helper_args) == -1) {
		pr_perror("amdgpu_plugin: failed to call helper ioctl\n");
		return -1;
	}

	args.num_of_devices = helper_args.num_of_devices;
	devinfo_bucket_ptr = xmalloc(helper_args.num_of_devices *
					sizeof(struct kfd_criu_devinfo_bucket));

	if (!devinfo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate devinfo for dumper ioctl\n");
		return -ENOMEM;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	pr_info("amdgpu_plugin: num of bos = %llu\n", helper_args.num_of_bos);

	bo_bucket_ptr = xmalloc(helper_args.num_of_bos *
			       sizeof(struct kfd_criu_bo_buckets));

	if (!bo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
		return -ENOMEM;
	}

	args.num_of_bos = helper_args.num_of_bos;
	args.kfd_criu_bo_buckets_ptr = (uintptr_t)bo_bucket_ptr;

	pr_info("amdgpu_plugin: num of queues = %u\n", helper_args.num_of_queues);

	q_bucket_ptr = xmalloc(helper_args.num_of_queues *
			       sizeof(struct kfd_criu_q_bucket));

	if (!q_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
		return -1;
	}

	args.num_of_queues = helper_args.num_of_queues;
	args.kfd_criu_q_buckets_ptr = (uintptr_t)q_bucket_ptr;

	if (helper_args.queues_data_size) {
		args.queues_data_ptr = (uintptr_t)xmalloc(helper_args.queues_data_size);
		if (!args.queues_data_ptr) {
			pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
			return -1;
		}
		args.queues_data_size = helper_args.queues_data_size;
		pr_info("amdgpu_plugin: queues data size:%llu\n", args.queues_data_size);
	}

	if (helper_args.num_of_events) {
		ev_buckets_ptr = xmalloc(helper_args.num_of_events *
					sizeof(struct kfd_criu_ev_bucket));
		args.num_of_events = helper_args.num_of_events;
	}

	args.kfd_criu_ev_buckets_ptr = (uintptr_t)ev_buckets_ptr;

	/* call dumper ioctl, pass num of BOs to dump */
        if (kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args) == -1) {
		pr_perror("amdgpu_plugin: failed to call kfd ioctl from plugin dumper for fd = %d\n", major(st.st_rdev));
		xfree(bo_bucket_ptr);
		return -1;
	}

	pr_info("amdgpu_plugin: success in calling dumper ioctl\n");

	e = xmalloc(sizeof(*e));
	if (!e) {
		pr_err("Failed to allocate proto structure\n");
		xfree(bo_bucket_ptr);
		return -ENOMEM;
	}

	criu_kfd__init(e);
	e->pid = helper_args.task_pid;

	/* When checkpointing on a node where there was already a checkpoint-restore before, the
	 * user_gpu_id and actual_gpu_id will be different.
	 *
	 * We store the user_gpu_id in the stored image files so that the stored images always have
	 * the gpu_id's of the node where the application was first launched. */
	for (int i = 0; i < args.num_of_devices; i++)
		maps_add_gpu_entry(&checkpoint_maps, devinfo_bucket_ptr[i].actual_gpu_id,
				   devinfo_bucket_ptr[i].user_gpu_id);

	ret = allocate_devinfo_entries(e, src_topology.num_nodes);
	if (ret) {
		ret = -ENOMEM;
		goto failed;
	}

	/* Store local topology information */
	ret = topology_to_devinfo(&src_topology, devinfo_bucket_ptr,
					&checkpoint_maps, e->devinfo_entries);
	if (ret)
		goto failed;

	e->num_of_gpus = args.num_of_devices;
	e->num_of_cpus = src_topology.num_nodes - args.num_of_devices;

	ret = allocate_bo_info_test(e, helper_args.num_of_bos, bo_bucket_ptr);
	if (ret)
		return -1;

	for (int i = 0; i < helper_args.num_of_bos; i++)
	{
		(e->bo_info_test[i])->bo_addr = (bo_bucket_ptr)[i].bo_addr;
		(e->bo_info_test[i])->bo_size = (bo_bucket_ptr)[i].bo_size;
		(e->bo_info_test[i])->bo_offset = (bo_bucket_ptr)[i].bo_offset;
		(e->bo_info_test[i])->bo_alloc_flags = (bo_bucket_ptr)[i].bo_alloc_flags;
		(e->bo_info_test[i])->idr_handle = (bo_bucket_ptr)[i].idr_handle;
		(e->bo_info_test[i])->user_addr = (bo_bucket_ptr)[i].user_addr;

		e->bo_info_test[i]->gpu_id = maps_get_dest_gpu(&checkpoint_maps,
							       bo_bucket_ptr[i].gpu_id);
		if (!e->bo_info_test[i]->gpu_id) {
			ret = -EFAULT;
			goto failed;
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
			pr_info("VRAM BO Found\n");
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			pr_info("GTT BO Found\n");
		}

		if ((bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    (bo_bucket_ptr)[i].bo_alloc_flags &
		    KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			char *fname;
			int mem_fd;

			if ((e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC) {
				int drm_fd;
				void *addr;
				struct tp_node *tp_node;


				plugin_log_msg("amdgpu_plugin: large bar read possible\n");

				tp_node = sys_get_node_by_gpu_id(&src_topology, (e->bo_info_test[i])->gpu_id);
				if (!tp_node) {
					ret = -EFAULT;
					goto failed;
				}

				drm_fd = open_drm_render_device(tp_node->drm_render_minor);
				if (drm_fd < 0) {
					ret = -EFAULT;
					goto failed;
				}

				addr = mmap(NULL,
					    (bo_bucket_ptr)[i].bo_size,
					    PROT_READ,
					    MAP_SHARED,
					    drm_fd,	/* mapping on local gpu for prototype */
					    (bo_bucket_ptr)[i].bo_offset);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					close(drm_fd);
					goto failed;
				}

				/* direct memcpy is possible on large bars */
				memcpy((e->bo_info_test[i])->bo_rawdata.data,
				       addr, bo_bucket_ptr[i].bo_size);
				munmap(addr, bo_bucket_ptr[i].bo_size);
				close(drm_fd);
			} else {
				plugin_log_msg("Now try reading BO contents with /proc/pid/mem");
				if (asprintf (&fname, PROCPIDMEM, e->pid) < 0) {
					pr_perror("failed in asprintf, %s\n", fname);
					ret = -1;
					goto failed;
				}

				mem_fd = open (fname, O_RDONLY);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d\n", fname, e->pid);
					free (fname);
					ret = -1;
					goto failed;
				}

				pr_info("Opened %s file for pid = %d\n", fname, e->pid);
				free (fname);
				if (lseek (mem_fd, (off_t) (bo_bucket_ptr)[i].bo_addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d\n", e->pid);
					ret = -1;
					goto failed;
				}
				pr_info("Try to read file now\n");

				if (read(mem_fd, e->bo_info_test[i]->bo_rawdata.data,
					 (e->bo_info_test[i])->bo_size) !=
				    (e->bo_info_test[i])->bo_size) {
					pr_perror("Can't read buffer\n");
					ret = -1;
					goto failed;
				}

				close(mem_fd);
			} /* PROCPIDMEM read done */
		}
	}
	e->num_of_bos = helper_args.num_of_bos;

	plugin_log_msg("Dumping bo_info_test \n");
	for (int i = 0; i < helper_args.num_of_bos; i++)
	{
		plugin_log_msg("e->bo_info_test[%d]:\n", i);
		plugin_log_msg("bo_addr = 0x%lx, bo_size = 0x%lx, bo_offset = 0x%lx, gpu_id = 0x%x, "
			"bo_alloc_flags = 0x%x, idr_handle = 0x%x\n",
		  (e->bo_info_test[i])->bo_addr,
		  (e->bo_info_test[i])->bo_size,
		  (e->bo_info_test[i])->bo_offset,
		  (e->bo_info_test[i])->gpu_id,
		  (e->bo_info_test[i])->bo_alloc_flags,
		  (e->bo_info_test[i])->idr_handle);
		plugin_log_msg("(bo_bucket_ptr)[%d]:\n", i);
		plugin_log_msg("bo_addr = 0x%llx, bo_size = 0x%llx, bo_offset = 0x%llx, "
			"gpu_id = 0x%x, bo_alloc_flags = 0x%x, idr_handle = 0x%x\n",
		  (bo_bucket_ptr)[i].bo_addr,
		  (bo_bucket_ptr)[i].bo_size,
		  (bo_bucket_ptr)[i].bo_offset,
		  (bo_bucket_ptr)[i].gpu_id,
		  (bo_bucket_ptr)[i].bo_alloc_flags,
		  (bo_bucket_ptr)[i].idr_handle);

	}

	ret = allocate_q_entries(e, helper_args.num_of_queues);
	if (ret)
		return ret;

	e->num_of_queues = helper_args.num_of_queues;

	for (int i = 0; i < e->num_of_queues; i++)
	{
		uint8_t *queue_data_ptr = (uint8_t *)args.queues_data_ptr
					+ q_bucket_ptr[i].queues_data_offset;

		plugin_log_msg("Dumping Queue[%d]:\n", i);
		plugin_log_msg("\tgpu_id:%x type:%x format:%x q_id:%x q_address:%llx ",
			q_bucket_ptr[i].gpu_id,
			q_bucket_ptr[i].type,
			q_bucket_ptr[i].format,
			q_bucket_ptr[i].q_id,
			q_bucket_ptr[i].q_address);

		e->q_entries[i]->gpu_id = maps_get_dest_gpu(&checkpoint_maps, q_bucket_ptr[i].gpu_id);
		if (!e->q_entries[i]->gpu_id) {
			ret = -EFAULT;
			goto failed;
		}

		e->q_entries[i]->type = q_bucket_ptr[i].type;
		e->q_entries[i]->format = q_bucket_ptr[i].format;
		e->q_entries[i]->q_id = q_bucket_ptr[i].q_id;
		e->q_entries[i]->q_address = q_bucket_ptr[i].q_address;
		e->q_entries[i]->q_size = q_bucket_ptr[i].q_size;
		e->q_entries[i]->priority = q_bucket_ptr[i].priority;
		e->q_entries[i]->q_percent = q_bucket_ptr[i].q_percent;
		e->q_entries[i]->read_ptr_addr = q_bucket_ptr[i].read_ptr_addr;
		e->q_entries[i]->write_ptr_addr = q_bucket_ptr[i].write_ptr_addr;
		e->q_entries[i]->doorbell_id = q_bucket_ptr[i].doorbell_id;
		e->q_entries[i]->doorbell_off = q_bucket_ptr[i].doorbell_off;
		e->q_entries[i]->is_gws = q_bucket_ptr[i].is_gws;
		e->q_entries[i]->sdma_id = q_bucket_ptr[i].sdma_id;
		e->q_entries[i]->eop_ring_buffer_address = q_bucket_ptr[i].eop_ring_buffer_address;
		e->q_entries[i]->eop_ring_buffer_size = q_bucket_ptr[i].eop_ring_buffer_size;
		e->q_entries[i]->ctx_save_restore_area_address = q_bucket_ptr[i].ctx_save_restore_area_address;
		e->q_entries[i]->ctx_save_restore_area_size = q_bucket_ptr[i].ctx_save_restore_area_size;
		e->q_entries[i]->ctl_stack_size = q_bucket_ptr[i].ctl_stack_size;

		e->q_entries[i]->cu_mask.len = q_bucket_ptr[i].cu_mask_size;
		e->q_entries[i]->cu_mask.data = queue_data_ptr;

		e->q_entries[i]->mqd.len = q_bucket_ptr[i].mqd_size;
		e->q_entries[i]->mqd.data = queue_data_ptr + q_bucket_ptr[i].cu_mask_size;

		e->q_entries[i]->ctl_stack.len = q_bucket_ptr[i].ctl_stack_size;
		e->q_entries[i]->ctl_stack.data = queue_data_ptr + q_bucket_ptr[i].cu_mask_size + q_bucket_ptr[i].mqd_size;
	}

	e->event_page_offset = args.event_page_offset;
	pr_info("amdgpu_plugin: number of events:%d\n", args.num_of_events);

	if (args.num_of_events) {
		ret = allocate_ev_entries(e, args.num_of_events);
		if (ret)
			return ret;

		for (int i = 0; i < args.num_of_events; i++) {
			e->ev_entries[i]->event_id = ev_buckets_ptr[i].event_id;
			e->ev_entries[i]->auto_reset = ev_buckets_ptr[i].auto_reset;
			e->ev_entries[i]->type = ev_buckets_ptr[i].type;
			e->ev_entries[i]->signaled = ev_buckets_ptr[i].signaled;

			if (e->ev_entries[i]->type == KFD_IOC_EVENT_MEMORY) {
				e->ev_entries[i]->mem_exc_fail_not_present =
					ev_buckets_ptr[i].memory_exception_data.failure.NotPresent;
				e->ev_entries[i]->mem_exc_fail_read_only =
					ev_buckets_ptr[i].memory_exception_data.failure.ReadOnly;
				e->ev_entries[i]->mem_exc_fail_no_execute =
					ev_buckets_ptr[i].memory_exception_data.failure.NoExecute;
				e->ev_entries[i]->mem_exc_va =
					ev_buckets_ptr[i].memory_exception_data.va;
				if (ev_buckets_ptr[i].memory_exception_data.gpu_id) {
					e->ev_entries[i]->mem_exc_gpu_id =
						maps_get_dest_gpu(&checkpoint_maps,
						ev_buckets_ptr[i].memory_exception_data.gpu_id);
					if (!&e->ev_entries[i]->mem_exc_gpu_id) {
						ret = -EFAULT;
						goto failed;
					}
				}
			} else if (e->ev_entries[i]->type == KFD_IOC_EVENT_HW_EXCEPTION) {
				e->ev_entries[i]->hw_exc_reset_type =
					ev_buckets_ptr[i].hw_exception_data.reset_type;
				e->ev_entries[i]->hw_exc_reset_cause =
					ev_buckets_ptr[i].hw_exception_data.reset_cause;
				e->ev_entries[i]->hw_exc_memory_lost =
					ev_buckets_ptr[i].hw_exception_data.memory_lost;
				if (ev_buckets_ptr[i].hw_exception_data.gpu_id) {
					e->ev_entries[i]->hw_exc_gpu_id =
						maps_get_dest_gpu(&checkpoint_maps,
						ev_buckets_ptr[i].hw_exception_data.gpu_id);

					if (!e->ev_entries[i]->hw_exc_gpu_id) {
						ret = -EFAULT;
						goto failed;
					}
				}
			}
		}
	}

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);
	pr_info("amdgpu_plugin: img_path = %s", img_path);

	len = criu_kfd__get_packed_size(e);

	pr_info("amdgpu_plugin: Len = %ld\n", len);

	buf = xmalloc(len);
	if (!buf) {
		pr_perror("failed to allocate memory\n");
		ret = -ENOMEM;
		goto failed;
	}

	criu_kfd__pack(e, buf);

	ret = write_file(img_path,  buf, len);
	if (ret)
		ret = -1;

	xfree(buf);
failed:
	xfree(devinfo_bucket_ptr);
	xfree(bo_bucket_ptr);
	xfree(q_bucket_ptr);
	if (ev_buckets_ptr)
		xfree(ev_buckets_ptr);
	free_e(e);
	pr_info("amdgpu_plugin: Exiting from dumper for fd = %d\n", major(st.st_rdev));
        return ret;

}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, amdgpu_plugin_dump_file)

int amdgpu_plugin_restore_file(int id)
{
	struct kfd_criu_devinfo_bucket *devinfo_bucket_ptr = NULL;
	int fd;
	struct kfd_ioctl_criu_restorer_args args = {0};
	struct kfd_criu_bo_buckets *bo_bucket_ptr;
	struct kfd_criu_q_bucket *q_bucket_ptr;
	struct kfd_criu_ev_bucket *ev_bucket_ptr = NULL;
	__u64 *restored_bo_offsets_array;
	char img_path[PATH_MAX];
	struct stat filestat;
	unsigned char *buf;
	CriuRenderNode *rd;
	char *fname;
	CriuKfd *e;
	void *addr;
	int j;

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

		if (stat(img_path, &filestat) == -1)
		{
			pr_perror("Failed to read file stats\n");
			return -1;
		}
		pr_info("renderD file size on disk = %ld\n", filestat.st_size);

		buf = xmalloc(filestat.st_size);
		if (!buf) {
			pr_perror("Failed to allocate memory\n");
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
			fd = -EBADFD;
			goto fail;
		}

		pr_info("amdgpu_plugin: render node gpu_id = 0x%04x\n", rd->gpu_id);

		target_gpu_id = maps_get_dest_gpu(&restore_maps, rd->gpu_id);
		if (!target_gpu_id) {
			fd = -EBADFD;
			goto fail;
		}

		tp_node = sys_get_node_by_gpu_id(&dest_topology, target_gpu_id);
		if (!tp_node) {
			fd = -EBADFD;
			goto fail;
		}

		pr_info("amdgpu_plugin: render node destination gpu_id = 0x%04x\n", tp_node->gpu_id);

		fd = open_drm_render_device(tp_node->drm_render_minor);
		if (fd < 0)
			pr_err("amdgpu_plugin: Failed to open render device (minor:%d)\n",
									tp_node->drm_render_minor);
fail:
		criu_render_node__free_unpacked(rd,  NULL);
		xfree(buf);
		return fd;
	}

	fd = open("/dev/kfd", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}
	pr_info("amdgpu_plugin: Opened kfd, fd = %d\n", fd);
	pr_info("kfd img file size on disk = %ld\n", filestat.st_size);

	buf = xmalloc(filestat.st_size);
	if (!buf) {
		pr_perror("Failed to allocate memory\n");
		return -ENOMEM;
	}

	if (read_file(img_path, buf, filestat.st_size)) {
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

	if (devinfo_to_topology(e->devinfo_entries, e->num_of_gpus + e->num_of_cpus, &src_topology)) {
		pr_err("Failed to convert stored device information to topology\n");
		xfree(buf);
		return -1;
	}

	if (topology_parse(&dest_topology, "Local")) {
		pr_err("Failed to parse local system topology\n");
		xfree(buf);
		return -1;
	}

	args.num_of_devices = e->num_of_gpus;

	devinfo_bucket_ptr = xmalloc(args.num_of_devices * sizeof(struct kfd_criu_devinfo_bucket));
	if (!devinfo_bucket_ptr) {
		fd = -EBADFD;
		goto clean;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	if (set_restore_gpu_maps(&src_topology, &dest_topology, &restore_maps)) {
		fd = -EBADFD;
		goto clean;
	}

	j = 0;
	for (int i = 0; i < e->num_of_gpus + e->num_of_cpus; i++) {
		struct tp_node *tp_node;
		int drm_fd;

		if (!e->devinfo_entries[i]->gpu_id)
			continue;

		devinfo_bucket_ptr[j].user_gpu_id = e->devinfo_entries[i]->gpu_id;

		devinfo_bucket_ptr[j].actual_gpu_id =
				maps_get_dest_gpu(&restore_maps, e->devinfo_entries[i]->gpu_id);

		if (!devinfo_bucket_ptr[j].actual_gpu_id) {
			fd = -EBADFD;
			goto clean;
		}

		tp_node = sys_get_node_by_gpu_id(&dest_topology,
							devinfo_bucket_ptr[j].actual_gpu_id);
		if (!tp_node) {
			fd = -EBADFD;
			goto clean;
		}

		drm_fd = open_drm_render_device(tp_node->drm_render_minor);
		if (drm_fd < 0) {
			fd = -EBADFD;
			goto clean;
		}
		devinfo_bucket_ptr[j].drm_fd = drm_fd;
		j++;
	}

	for (int i = 0; i < e->num_of_bos; i++ )
	{
		plugin_log_msg("reading e->bo_info_test[%d]:\n", i);
		plugin_log_msg("bo_addr = 0x%lx, bo_size = 0x%lx, bo_offset = 0x%lx, "
			"gpu_id = 0x%x, bo_alloc_flags = 0x%x, idr_handle = 0x%x user_addr=0x%lx\n",
		  (e->bo_info_test[i])->bo_addr,
		  (e->bo_info_test[i])->bo_size,
		  (e->bo_info_test[i])->bo_offset,s
		  (e->bo_info_test[i])->gpu_id,
		  (e->bo_info_test[i])->bo_alloc_flags,
		  (e->bo_info_test[i])->idr_handle,
		  (e->bo_info_test[i])->user_addr);
	}

	bo_bucket_ptr = xmalloc(e->num_of_bos *
			       sizeof(struct kfd_criu_bo_buckets));

	if (!bo_bucket_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for restorer ioctl\n");
		return -1;
	}

	for (int i = 0; i < e->num_of_bos; i++)
	{
		(bo_bucket_ptr)[i].bo_addr = (e->bo_info_test[i])->bo_addr;
		(bo_bucket_ptr)[i].bo_size = (e->bo_info_test[i])->bo_size;
		(bo_bucket_ptr)[i].bo_offset = (e->bo_info_test[i])->bo_offset;
		(bo_bucket_ptr)[i].bo_alloc_flags = (e->bo_info_test[i])->bo_alloc_flags;
		(bo_bucket_ptr)[i].idr_handle = (e->bo_info_test[i])->idr_handle;
		(bo_bucket_ptr)[i].user_addr = (e->bo_info_test[i])->user_addr;

		bo_bucket_ptr[i].gpu_id =
				maps_get_dest_gpu(&restore_maps, e->bo_info_test[i]->gpu_id);
		if (!bo_bucket_ptr[i].gpu_id) {
			fd = -EBADFD;
			goto clean;
		}
	}

	args.num_of_bos = e->num_of_bos;
	args.kfd_criu_bo_buckets_ptr = (uintptr_t)bo_bucket_ptr;

	restored_bo_offsets_array = xmalloc(sizeof(uint64_t) * e->num_of_bos);
	if (!restored_bo_offsets_array) {
		xfree(bo_bucket_ptr);
		return -ENOMEM;
	}

	args.restored_bo_array_ptr = (uint64_t)restored_bo_offsets_array;

	q_bucket_ptr = xmalloc(e->num_of_queues * sizeof(struct kfd_criu_q_bucket));
        if (!q_bucket_ptr) {
               pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
               return -1;
	}

	pr_info("Number of queues:%u\n", e->num_of_queues);

	args.queues_data_size = 0;
	for (int i = 0; i < e->num_of_queues; i++ ) {
		args.queues_data_size += e->q_entries[i]->cu_mask.len
					+ e->q_entries[i]->mqd.len
					+ e->q_entries[i]->ctl_stack.len;
	}

	pr_info("Queues data size:%llu\n", args.queues_data_size);

	args.queues_data_ptr = (uintptr_t)xmalloc(args.queues_data_size);
	if (!args.queues_data_ptr) {
		pr_perror("amdgpu_plugin: failed to allocate args for dumper ioctl\n");
		return -1;
	}

	uint32_t queues_data_offset = 0;

	for (int i = 0; i < e->num_of_queues; i++ )
	{
		uint8_t *queue_data;
		plugin_log_msg("Restoring Queue[%d]:\n", i);
		plugin_log_msg("\tgpu_id:%x type:%x format:%x q_id:%x q_address:%lx "
			"cu_mask_size:%lx mqd_size:%lx ctl_stack_size:%lx\n",
			e->q_entries[i]->gpu_id,
			e->q_entries[i]->type,
			e->q_entries[i]->format,
			e->q_entries[i]->q_id,
			e->q_entries[i]->q_address,
			e->q_entries[i]->cu_mask.len,
			e->q_entries[i]->mqd.len,
			e->q_entries[i]->ctl_stack.len);

		q_bucket_ptr[i].gpu_id = maps_get_dest_gpu(&restore_maps, e->q_entries[i]->gpu_id);
		if (!q_bucket_ptr[i].gpu_id) {
			fd = -EBADFD;
			goto clean;
		}

		q_bucket_ptr[i].type = e->q_entries[i]->type;
		q_bucket_ptr[i].format = e->q_entries[i]->format;
		q_bucket_ptr[i].q_id = e->q_entries[i]->q_id;
		q_bucket_ptr[i].q_address = e->q_entries[i]->q_address;
		q_bucket_ptr[i].q_size = e->q_entries[i]->q_size;
		q_bucket_ptr[i].priority = e->q_entries[i]->priority;
		q_bucket_ptr[i].q_percent = e->q_entries[i]->q_percent;
		q_bucket_ptr[i].read_ptr_addr = e->q_entries[i]->read_ptr_addr;
		q_bucket_ptr[i].write_ptr_addr = e->q_entries[i]->write_ptr_addr;
		q_bucket_ptr[i].doorbell_id = e->q_entries[i]->doorbell_id;
		q_bucket_ptr[i].doorbell_off = e->q_entries[i]->doorbell_off;
		q_bucket_ptr[i].is_gws = e->q_entries[i]->is_gws;
		q_bucket_ptr[i].sdma_id = e->q_entries[i]->sdma_id;
		q_bucket_ptr[i].eop_ring_buffer_address = e->q_entries[i]->eop_ring_buffer_address;
		q_bucket_ptr[i].eop_ring_buffer_size = e->q_entries[i]->eop_ring_buffer_size;
		q_bucket_ptr[i].ctx_save_restore_area_address = e->q_entries[i]->ctx_save_restore_area_address;
		q_bucket_ptr[i].ctx_save_restore_area_size = e->q_entries[i]->ctx_save_restore_area_size;
		q_bucket_ptr[i].ctl_stack_size = e->q_entries[i]->ctl_stack_size;

		q_bucket_ptr[i].queues_data_offset = queues_data_offset;
		queue_data = (uint8_t *)args.queues_data_ptr + queues_data_offset;

		q_bucket_ptr[i].cu_mask_size = e->q_entries[i]->cu_mask.len;
		memcpy(queue_data,
			e->q_entries[i]->cu_mask.data,
			e->q_entries[i]->cu_mask.len);

		q_bucket_ptr[i].mqd_size = e->q_entries[i]->mqd.len;
		memcpy(queue_data + e->q_entries[i]->cu_mask.len,
			e->q_entries[i]->mqd.data,
			e->q_entries[i]->mqd.len);

		q_bucket_ptr[i].ctl_stack_size = e->q_entries[i]->ctl_stack.len;
		memcpy(queue_data + e->q_entries[i]->cu_mask.len + e->q_entries[i]->mqd.len,
			e->q_entries[i]->ctl_stack.data,
			e->q_entries[i]->ctl_stack.len);

		queues_data_offset += e->q_entries[i]->cu_mask.len
					+ e->q_entries[i]->mqd.len
					+ e->q_entries[i]->ctl_stack.len;

	}

	args.num_of_queues = e->num_of_queues;
	args.kfd_criu_q_buckets_ptr = (uintptr_t)q_bucket_ptr;

	args.event_page_offset = e->event_page_offset;

	pr_info("Number of events:%u\n", e->num_of_events);
	if (e->num_of_events) {
		ev_bucket_ptr = xmalloc(e->num_of_events * sizeof(struct kfd_criu_ev_bucket));
		if (!ev_bucket_ptr) {
			pr_perror("amdgpu_plugin: failed to allocate events for restore ioctl\n");
			return -1;
		}

		for (int i = 0; i < e->num_of_events; i++ )
		{
			ev_bucket_ptr[i].event_id = e->ev_entries[i]->event_id;
			ev_bucket_ptr[i].auto_reset = e->ev_entries[i]->auto_reset;
			ev_bucket_ptr[i].type = e->ev_entries[i]->type;
			ev_bucket_ptr[i].signaled = e->ev_entries[i]->signaled;

			if (e->ev_entries[i]->type == KFD_IOC_EVENT_MEMORY) {
				ev_bucket_ptr[i].memory_exception_data.failure.NotPresent =
						e->ev_entries[i]->mem_exc_fail_not_present;
				ev_bucket_ptr[i].memory_exception_data.failure.ReadOnly =
						e->ev_entries[i]->mem_exc_fail_read_only;
				ev_bucket_ptr[i].memory_exception_data.failure.NoExecute =
						e->ev_entries[i]->mem_exc_fail_no_execute;
				ev_bucket_ptr[i].memory_exception_data.va =
						e->ev_entries[i]->mem_exc_va;
				if (e->ev_entries[i]->mem_exc_gpu_id) {
					ev_bucket_ptr[i].memory_exception_data.gpu_id =
						maps_get_dest_gpu(&restore_maps,
								  e->ev_entries[i]->mem_exc_gpu_id);
					if (!ev_bucket_ptr[i].memory_exception_data.gpu_id) {
						fd = -EBADFD;
						goto clean;
					}
				}
			} else if (e->ev_entries[i]->type == KFD_IOC_EVENT_HW_EXCEPTION) {
				ev_bucket_ptr[i].hw_exception_data.reset_type =
					e->ev_entries[i]->hw_exc_reset_type;
				ev_bucket_ptr[i].hw_exception_data.reset_cause =
					e->ev_entries[i]->hw_exc_reset_cause;
				ev_bucket_ptr[i].hw_exception_data.memory_lost =
					e->ev_entries[i]->hw_exc_memory_lost;

				if (e->ev_entries[i]->hw_exc_gpu_id) {
					ev_bucket_ptr[i].hw_exception_data.gpu_id =
						maps_get_dest_gpu(&restore_maps,
								 e->ev_entries[i]->hw_exc_gpu_id);

					if (!ev_bucket_ptr[i].memory_exception_data.gpu_id) {
						fd = -EBADFD;
						goto clean;
					}
				}
			}
		}

		args.num_of_events = e->num_of_events;
		args.kfd_criu_ev_buckets_ptr = (uintptr_t)ev_bucket_ptr;
	}

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESTORER, &args) == -1) {
		pr_perror("amdgpu_plugin: failed to call kfd ioctl from plugin restorer for id = %d\n", id);
		fd = -EBADFD;
		goto clean;
	}

	for (int i = 0; i < e->num_of_bos; i++)
	{
		if (e->bo_info_test[i]->bo_alloc_flags &
			(KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			 KFD_IOC_ALLOC_MEM_FLAGS_GTT |
			 KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP |
			 KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL)) {

			struct tp_node *tp_node;
			struct vma_metadata *vma_md;
			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md)
				return -ENOMEM;

			memset(vma_md, 0, sizeof(*vma_md));

			vma_md->old_pgoff = bo_bucket_ptr[i].bo_offset;
			vma_md->vma_entry = bo_bucket_ptr[i].bo_addr;

			tp_node = sys_get_node_by_gpu_id(&dest_topology, bo_bucket_ptr[i].gpu_id);
			if (!tp_node) {
				pr_err("Failed to find node with gpu_id:0x%04x\n", bo_bucket_ptr[i].gpu_id);
				fd = -EBADFD;
				goto clean;
			}
			vma_md->new_minor = tp_node->drm_render_minor;

			vma_md->new_pgoff = restored_bo_offsets_array[i];

			plugin_log_msg("amdgpu_plugin: adding vma_entry:addr:0x%lx old-off:0x%lx \
					new_off:0x%lx new_minor:%d\n", vma_md->vma_entry,
					vma_md->old_pgoff, vma_md->new_pgoff, vma_md->new_minor);

			list_add_tail(&vma_md->list, &update_vma_info_list);
		}

		if (e->bo_info_test[i]->bo_alloc_flags &
			(KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {

			int j;
			int drm_render_fd = -EBADFD;

			for (j = 0; j < e->num_of_gpus; j++) {
				if (devinfo_bucket_ptr[j].actual_gpu_id == bo_bucket_ptr[i].gpu_id) {
					drm_render_fd = devinfo_bucket_ptr[j].drm_fd;
					break;
				}
			}

			if (drm_render_fd < 0) {
				pr_err("amdgpu_plugin: bad fd for render node\n");
				fd = -EBADFD;
				goto clean;
			}

			plugin_log_msg("amdgpu_plugin: Trying mmap in stage 2\n");
			if ((e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC ||
			    (e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_GTT ) {
				plugin_log_msg("amdgpu_plugin: large bar write possible\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_WRITE,
					    MAP_SHARED,
					    drm_render_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					goto clean;
				}

				/* direct memcpy is possible on large bars */
				memcpy(addr, (void *)e->bo_info_test[i]->bo_rawdata.data,
				       (e->bo_info_test[i])->bo_size);
				munmap(addr, e->bo_info_test[i]->bo_size);
			} else {
				int mem_fd;
				/* Use indirect host data path via /proc/pid/mem
				 * on small pci bar GPUs or for Buffer Objects
				 * that don't have HostAccess permissions.
				 */
				plugin_log_msg("amdgpu_plugin: using PROCPIDMEM to restore BO contents\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_NONE,
					    MAP_SHARED,
					    drm_render_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("amdgpu_plugin: mmap failed\n");
					fd = -EBADFD;
					goto clean;
				}

				if (asprintf (&fname, PROCPIDMEM, e->pid) < 0) {
					pr_perror("failed in asprintf, %s\n", fname);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				mem_fd = open (fname, O_RDWR);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d\n", fname, e->pid);
					free (fname);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				plugin_log_msg("Opened %s file for pid = %d\n", fname, e->pid);
				free (fname);

				if (lseek (mem_fd, (off_t) addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d\n", e->pid);
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}

				plugin_log_msg("Attempt writting now\n");
				if (write(mem_fd, e->bo_info_test[i]->bo_rawdata.data,
					  (e->bo_info_test[i])->bo_size) !=
				    (e->bo_info_test[i])->bo_size) {
					pr_perror("Can't write buffer\n");
					munmap(addr, e->bo_info_test[i]->bo_size);
					fd = -EBADFD;
					goto clean;
				}
				munmap(addr, e->bo_info_test[i]->bo_size);
				close(mem_fd);
			}
		} else {
			pr_info("Not a VRAM BO\n");
			continue;
		}
	} /* mmap done for VRAM BO */

	for (int i = 0; i < e->num_of_gpus; i++) {
		if (devinfo_bucket_ptr[i].drm_fd >= 0)
			close(devinfo_bucket_ptr[i].drm_fd);
	}
clean:
	xfree(devinfo_bucket_ptr);
	if (ev_bucket_ptr)
		xfree(ev_bucket_ptr);
	if (q_bucket_ptr)
		xfree(q_bucket_ptr);
	xfree(restored_bo_offsets_array);
	xfree(bo_bucket_ptr);
	xfree(buf);
	if (args.queues_data_ptr)
		xfree((void*)args.queues_data_ptr);

	criu_kfd__free_unpacked(e, NULL);
	pr_info("amdgpu_plugin: returning kfd fd from plugin, fd = %d\n", fd);
	return fd;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, amdgpu_plugin_restore_file)

/* return 0 if no match found
 * return -1 for error.
 * return 1 if vmap map must be adjusted. */
int amdgpu_plugin_update_vmamap(const char *old_path, char *new_path, const uint64_t addr,
				const uint64_t old_offset, uint64_t *new_offset)
{
	struct vma_metadata *vma_md;
	char path[PATH_MAX];
	char *p_begin;
	char *p_end;
	bool is_kfd = false, is_renderD = false;


	pr_info("amdgpu_plugin: Enter %s\n", __func__);

	strncpy(path, old_path, sizeof(path));

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

	if (!strcmp(path, "/dev/kfd"))
		is_kfd = true;

	if (!is_renderD && !is_kfd) {
		pr_info("Skipping unsupported path:%s addr:%lx old_offset:%lx\n", old_path, addr, old_offset);
		return 0;
	}

	list_for_each_entry(vma_md, &update_vma_info_list, list) {
		if (addr == vma_md->vma_entry && old_offset == vma_md->old_pgoff) {
			*new_offset = vma_md->new_pgoff;

			if (is_renderD)
				sprintf(new_path, "/dev/dri/renderD%d", vma_md->new_minor);
			else
				strcpy(new_path, old_path);

			pr_info("amdgpu_plugin: old_pgoff= 0x%lx new_pgoff = 0x%lx old_path = %s new_path = %s\n",
				vma_md->old_pgoff, vma_md->new_pgoff, old_path, new_path);

			return 1;
		}
	}
	pr_info("No match for addr:0x%lx offset:%lx\n", addr, old_offset);
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, amdgpu_plugin_update_vmamap)

int amdgpu_plugin_resume_devices_late(int target_pid)
{
	struct kfd_ioctl_criu_resume_args args = {0};
	int fd, ret = 0;

	pr_info("amdgpu_plugin: Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open("/dev/kfd", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	args.pid = target_pid;
	pr_info("amdgpu_plugin: Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESUME, &args) == -1) {
		pr_perror("restore late ioctl failed\n");
		ret = -1;
	}

	close(fd);
	return ret;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, amdgpu_plugin_resume_devices_late)
