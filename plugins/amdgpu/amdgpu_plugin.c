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

#define AMDGPU_KFD_DEVICE "/dev/kfd"
#define PROCPIDMEM	  "/proc/%d/mem"

#define KFD_IOCTL_MAJOR_VERSION	    1
#define MIN_KFD_IOCTL_MINOR_VERSION 7

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
};

/************************************ Global Variables ********************************************/
struct tp_system src_topology;
struct tp_system dest_topology;

struct device_maps checkpoint_maps;
struct device_maps restore_maps;

static LIST_HEAD(update_vma_info_list);
/**************************************************************************************************/

int open_drm_render_device(int minor)
{
	char path[128];
	int fd;

	if (minor < DRM_FIRST_RENDER_NODE || minor > DRM_LAST_RENDER_NODE) {
		pr_perror("DRM render minor %d out of range [%d, %d]", minor, DRM_FIRST_RENDER_NODE,
			  DRM_LAST_RENDER_NODE);
		return -EINVAL;
	}

	snprintf(path, sizeof(path), "/dev/dri/renderD%d", minor);
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
		if (e->bo_entries[i]) {
			if (e->bo_entries[i]->rawdata.data)
				xfree(e->bo_entries[i]->rawdata.data);

			xfree(e->bo_entries[i]);
		}
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

int topology_to_devinfo(struct tp_system *sys, struct device_maps *maps, DeviceEntry **deviceEntries)
{
	uint32_t devinfo_index = 0;
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		DeviceEntry *devinfo = deviceEntries[devinfo_index++];

		devinfo->node_id = node->id;

		if (NODE_IS_GPU(node)) {
			devinfo->gpu_id = node->gpu_id;

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

	return 0;
}

void amdgpu_plugin_fini(int stage, int ret)
{
	pr_info("amdgpu_plugin: finished  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);

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

static int unpause_process(int fd)
{
	int ret = 0;
	struct kfd_ioctl_criu_args args = { 0 };

	args.op = KFD_CRIU_OP_UNPAUSE;

	ret = kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args);
	if (ret) {
		pr_perror("amdgpu_plugin: Failed to unpause process");
		goto exit;
	}

exit:
	pr_info("Process unpaused %s (ret:%d)\n", ret ? "Failed" : "Ok", ret);

	return ret;
}

static int save_devices(int fd, struct kfd_ioctl_criu_args *args, struct kfd_criu_device_bucket *device_buckets,
			CriuKfd *e)
{
	int ret = 0;

	pr_debug("Dumping %d devices\n", args->num_devices);

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

static int save_bos(int fd, struct kfd_ioctl_criu_args *args, struct kfd_criu_bo_bucket *bo_buckets, CriuKfd *e)
{
	int ret = 0, i;
	char *fname;

	pr_debug("Dumping %d BOs\n", args->num_bos);

	e->num_of_bos = args->num_bos;
	ret = allocate_bo_entries(e, e->num_of_bos, bo_buckets);
	if (ret)
		goto exit;

	for (i = 0; i < e->num_of_bos; i++) {
		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		BoEntry *boinfo = e->bo_entries[i];

		boinfo->gpu_id = bo_bucket->gpu_id;
		boinfo->addr = bo_bucket->addr;
		boinfo->size = bo_bucket->size;
		boinfo->offset = bo_bucket->offset;
		boinfo->alloc_flags = bo_bucket->alloc_flags;

		if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM ||
		    bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
			if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC) {
				void *addr;

				pr_info("amdgpu_plugin: large bar read possible\n");

				addr = mmap(NULL, boinfo->size, PROT_READ, MAP_SHARED, fd, boinfo->offset);
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

				pr_info("Now try reading BO contents with /proc/pid/mem\n");
				if (asprintf(&fname, PROCPIDMEM, args->pid) < 0) {
					pr_perror("failed in asprintf, %s", fname);
					ret = -1;
					goto exit;
				}

				mem_fd = open(fname, O_RDONLY);
				if (mem_fd < 0) {
					pr_perror("Can't open %s for pid %d", fname, args->pid);
					free(fname);
					close(mem_fd);
					ret = -1;
					goto exit;
				}

				pr_info("Opened %s file for pid = %d\n", fname, args->pid);
				free(fname);

				if (lseek(mem_fd, (off_t)bo_bucket->addr, SEEK_SET) == -1) {
					pr_perror("Can't lseek for bo_offset for pid = %d", args->pid);
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
		pr_perror("amdgpu_plugin: Failed to call get version ioctl");
		ret = false;
		goto exit;
	}

	pr_debug("Kernel IOCTL version:%d.%02d\n", args.major_version, args.minor_version);

	if (args.major_version != KFD_IOCTL_MAJOR_VERSION || args.minor_version < MIN_KFD_IOCTL_MINOR_VERSION) {
		pr_err("amdgpu_plugin: CR not supported on current kernel (current:%02d.%02d min:%02d.%02d)\n",
		       args.major_version, args.minor_version, KFD_IOCTL_MAJOR_VERSION, MIN_KFD_IOCTL_MINOR_VERSION);
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
		/* This is RenderD dumper plugin, for now just save renderD
		 * minor number to be used during restore. In later phases this
		 * needs to save more data for video decode etc.
		 */

		CriuRenderNode rd = CRIU_RENDER_NODE__INIT;

		pr_info("amdgpu_plugin: Dumper called for /dev/dri/renderD%d, FD = %d, ID = %d\n", minor(st.st_rdev),
			fd, id);

		rd.minor_number = minor(st.st_rdev);

		len = criu_render_node__get_packed_size(&rd);
		buf = xmalloc(len);
		if (!buf)
			return -ENOMEM;

		criu_render_node__pack(&rd, buf);

		snprintf(img_path, sizeof(img_path), "amdgpu-renderD-%d.img", id);
		ret = write_file(img_path, buf, len);
		if (ret) {
			xfree(buf);
			return ret;
		}

		xfree(buf);
		/* Need to return success here so that criu can call plugins for renderD nodes */
		return ret;
	}

	pr_info("amdgpu_plugin: %s : %s() called for fd = %d\n", CR_PLUGIN_DESC.name, __func__, major(st.st_rdev));

	/* KFD only allows ioctl calls from the same process that opened the KFD file descriptor.
	 * The existing /dev/kfd file descriptor that is passed in is only allowed to do IOCTL calls with
	 * CAP_CHECKPOINT_RESTORE/CAP_SYS_ADMIN. So kernel_supports_criu() needs to open its own file descriptor to
	 * perform the AMDKFD_IOC_GET_VERSION ioctl.
	 */
	if (!kernel_supports_criu(-1))
		return -ENOTSUP;

	args.op = KFD_CRIU_OP_PROCESS_INFO;
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args) == -1) {
		pr_perror("amdgpu_plugin: Failed to call process info ioctl");
		ret = -1;
		goto exit;
	}

	pr_info("amdgpu_plugin: devices:%d bos:%d objects:%d priv_data:%lld\n", args.num_devices, args.num_bos,
		args.num_objects, args.priv_data_size);

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
		pr_perror("amdgpu_plugin: Failed to call dumper (process) ioctl");
		goto exit;
	}

	ret = save_devices(fd, &args, (struct kfd_criu_device_bucket *)args.devices, e);
	if (ret)
		goto exit;

	ret = save_bos(fd, &args, (struct kfd_criu_bo_bucket *)args.bos, e);
	if (ret)
		goto exit;

	e->num_of_objects = args.num_objects;

	e->priv_data.data = (void *)args.priv_data;
	e->priv_data.len = args.priv_data_size;

	snprintf(img_path, sizeof(img_path), "amdgpu-kfd-%d.img", id);
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
	unpause_process(fd);

	xfree((void *)args.devices);
	xfree((void *)args.bos);
	xfree((void *)args.priv_data);

	free_e(e);

	if (ret)
		pr_err("amdgpu_plugin: Failed to dump (ret:%d)\n", ret);
	else
		pr_info("amdgpu_plugin: Dump successful\n");

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
		DeviceEntry *devinfo = e->device_entries[entries_i];

		if (!devinfo->gpu_id)
			continue;

		device_bucket = &device_buckets[bucket_index++];

		device_bucket->user_gpu_id = devinfo->gpu_id;

		device_bucket->drm_fd = open_drm_render_device(bucket_index + DRM_FIRST_RENDER_NODE);
		if (device_bucket->drm_fd < 0) {
			pr_perror("amdgpu_plugin: Can't pass NULL drm render fd to driver");
			goto exit;
		} else {
			pr_info("amdgpu_plugin: passing drm render fd = %d to driver\n", device_bucket->drm_fd);
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
		BoEntry *bo_entry = e->bo_entries[i];

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

static int restore_bo_data(int fd, struct kfd_criu_bo_bucket *bo_buckets, CriuKfd *e)
{
	int mem_fd = -1;

	for (int i = 0; i < e->num_of_bos; i++) {
		void *addr;

		struct kfd_criu_bo_bucket *bo_bucket = &bo_buckets[i];
		BoEntry *bo_entry = e->bo_entries[i];

		if (bo_bucket->alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT |
					      KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP | KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL)) {
			struct vma_metadata *vma_md;

			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md)
				return -ENOMEM;

			vma_md->old_pgoff = bo_bucket->offset;
			vma_md->vma_entry = bo_bucket->addr;
			vma_md->new_pgoff = bo_bucket->restored_offset;

			plugin_log_msg("amdgpu_plugin: adding vma_entry:addr:0x%lx old-off:0x%lx "
				       "new_off:0x%lx new_minor:%d\n",
				       vma_md->vma_entry, vma_md->old_pgoff, vma_md->new_pgoff, vma_md->new_minor);

			list_add_tail(&vma_md->list, &update_vma_info_list);
		}

		if (bo_bucket->alloc_flags & (KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {
			pr_info("amdgpu_plugin: Trying mmap in stage 2\n");
			if (bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC ||
			    bo_bucket->alloc_flags & KFD_IOC_ALLOC_MEM_FLAGS_GTT) {
				plugin_log_msg("amdgpu_plugin: large bar write possible\n");
				addr = mmap(NULL, bo_bucket->size, PROT_WRITE, MAP_SHARED, fd,
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
				char *fname;
				/* Use indirect host data path via /proc/pid/mem
				 * on small pci bar GPUs or for Buffer Objects
				 * that don't have HostAccess permissions.
				 */
				plugin_log_msg("amdgpu_plugin: using PROCPIDMEM to restore BO contents\n");
				addr = mmap(NULL, bo_bucket->size, PROT_NONE, MAP_SHARED, fd,
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
	if (mem_fd > 0)
		close(mem_fd);

	return 0;
}

int amdgpu_plugin_restore_file(int id)
{
	int ret = 0, fd;
	char img_path[PATH_MAX];
	struct stat filestat;
	unsigned char *buf;
	CriuRenderNode *rd;
	CriuKfd *e = NULL;
	struct kfd_ioctl_criu_args args = { 0 };

	pr_info("amdgpu_plugin: Initialized kfd plugin restorer with ID = %d\n", id);

	snprintf(img_path, sizeof(img_path), "amdgpu-kfd-%d.img", id);

	if (stat(img_path, &filestat) == -1) {
		pr_perror("open(%s)", img_path);
		/* This is restorer plugin for renderD nodes. Since criu doesn't
		 * gurantee that they will be called before the plugin is called
		 * for kfd file descriptor, we need to make sure we open the render
		 * nodes only once and before /dev/kfd is open, the render nodes
		 * are open too. Generally, it is seen that during checkpoint and
		 * restore both, the kfd plugin gets called first.
		 */
		snprintf(img_path, sizeof(img_path), "amdgpu-renderD-%d.img", id);

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

		pr_info("amdgpu_plugin: render node minor num = %d\n", rd->minor_number);
		fd = open_drm_render_device(rd->minor_number);
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

	if (!kernel_supports_criu(fd))
		return -ENOTSUP;

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

	ret = restore_bo_data(fd, (struct kfd_criu_bo_bucket *)args.bos, e);
	if (ret)
		goto exit;

exit:
	if (e)
		criu_kfd__free_unpacked(e, NULL);

	xfree((void *)args.devices);
	xfree((void *)args.bos);
	xfree(buf);

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
int amdgpu_plugin_update_vmamap(const char *path, const uint64_t addr, const uint64_t old_offset, uint64_t *new_offset,
				int *updated_fd)
{
	struct vma_metadata *vma_md;

	plugin_log_msg("amdgpu_plugin: Enter %s\n", __func__);

	/*
	 * On newer versions of AMD KFD driver, only the file descriptor that was used to open the
	 * device can be used for mmap, so we will have to return the proper file descriptor here
	 */
	*updated_fd = -1;

	list_for_each_entry(vma_md, &update_vma_info_list, list) {
		if (addr == vma_md->vma_entry && old_offset == vma_md->old_pgoff) {
			*new_offset = vma_md->new_pgoff;

			plugin_log_msg("amdgpu_plugin: old_pgoff= 0x%lx new_pgoff = 0x%lx path = %s\n",
				       vma_md->old_pgoff, vma_md->new_pgoff, path);

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
	int fd, ret = 0;

	pr_info("amdgpu_plugin: Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open(AMDGPU_KFD_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	args.pid = target_pid;
	args.op = KFD_CRIU_OP_RESUME;
	pr_info("amdgpu_plugin: Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_OP, &args) == -1) {
		pr_perror("restore late ioctl failed");
		ret = -1;
	}

	close(fd);
	return ret;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, amdgpu_plugin_resume_devices_late)
