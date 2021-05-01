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
#include <dirent.h>

#include "criu-plugin.h"
#include "criu-kfd.pb-c.h"

#include "kfd_ioctl.h"
#include "xmalloc.h"
#include "criu-log.h"

#include "common/list.h"

#define DRM_FIRST_RENDER_NODE 128
#define DRM_LAST_RENDER_NODE 255

#define PROCPIDMEM      "/proc/%d/mem"
#define TOPOLOGY_PATH   "/sys/class/kfd/kfd/topology/nodes/"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "kfd_plugin: "

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

struct tp_system {
	bool parsed;
	int num_nodes;
	struct tp_device {
		uint32_t gpu_id;
		uint32_t cpu_cores_count;
		uint32_t simd_count;
		uint32_t mem_banks_count;
		uint32_t caches_count;
		uint32_t io_links_count;
		uint32_t cpu_core_id_base;
		uint32_t simd_id_base;
		uint32_t max_waves_per_simd;
		uint32_t lds_size_in_kb;
		uint32_t gds_size_in_kb;
		uint32_t num_gws;
		uint32_t wave_front_size;
		uint32_t array_count;
		uint32_t simd_arrays_per_engine;
		uint32_t cu_per_simd_array;
		uint32_t simd_per_cu;
		uint32_t max_slots_scratch_cu;
		uint32_t vendor_id;
		uint32_t device_id;
		uint32_t domain;
		uint32_t drm_render_minor;
		uint64_t hive_id;
		uint32_t num_sdma_engines;
		uint32_t num_sdma_xgmi_engines;
		uint32_t num_sdma_queues_per_engine;
		uint32_t num_cp_queues;
		uint64_t local_mem_size;
		uint32_t fw_version;
		uint32_t capability;
		uint32_t sdma_fw_version;
	} devs[NUM_OF_SUPPORTED_GPUS];
};

struct tp_system src_topology;  /* Valid during dump */
struct tp_system dest_topology; /* Valid during restore */

struct gpu_id_maps {
	uint32_t num_devices;
	struct gpu_id_map {
		uint32_t src;
		uint32_t dest;
	} maps[NUM_OF_SUPPORTED_GPUS];
};

/* Valid during dump, map of actual gpu_id to user gpu_id */
struct gpu_id_maps checkpoint_maps;

/* Valid during restore, map of gpu_id on checkpointed node to gpu_id on current node */
struct gpu_id_maps restore_maps;

struct tp_device *get_tp_device_by_render_minor(struct tp_system *sys, int drm_render_minor)
{
	int i;
	for (i = 0; i < sys->num_nodes; i++) {
		if (sys->devs[i].drm_render_minor == drm_render_minor)
			return &sys->devs[i];
	}
	pr_err("Failed to find device with drm_render_minor = 0x%x\n", drm_render_minor);
	return NULL;
}

struct tp_device *get_tp_device_by_gpu_id(struct tp_system *sys, int gpu_id)
{
	int i;
	for (i = 0; i < sys->num_nodes; i++) {
		if (sys->devs[i].gpu_id == gpu_id)
			return &sys->devs[i];
	}
	pr_err("Failed to find device with gpu_id = 0x%x\n", gpu_id);
	return NULL;
}

/* Returns 0 if successfull or name did not match. -errno if fail to parse  */
int get_prop_uint64(const char *line, const char *name, uint64_t *value)
{
	char *p_val_begin, *p_val_end;
	char value_str[25];

	if (strncmp(line, name, strlen(name)))
		return 0;

	memset(value_str, 0, sizeof(value_str));

	p_val_begin = strchr(line, ' ');
	if (p_val_begin && *p_val_begin == ' ')
		p_val_begin++;

	if (!p_val_begin)
		return -EINVAL;

	p_val_end = strchr(p_val_begin, '\n');
	if (!p_val_end)
		return -EINVAL;

	if (p_val_end - p_val_begin > sizeof(value_str))
		return -EINVAL;

	strncpy(value_str, p_val_begin, p_val_end - p_val_begin);
	if (sscanf(value_str, "%lu", value) != 1)
		return -EINVAL;

	return 0;
}

/* Returns 0 if successfull or name did not match. -errno if fail to parse  */
int get_prop_uint32(const char *line, const char *name, uint32_t *value)
{
	char *p_val_begin, *p_val_end;
	char value_str[15];

	if (strncmp(line, name, strlen(name)))
		return 0;

	memset(value_str, 0, sizeof(value_str));

	p_val_begin = strchr(line, ' ');
	if (p_val_begin && *p_val_begin == ' ')
		p_val_begin++;

	if (!p_val_begin)
		return -EINVAL;

	p_val_end = strchr(p_val_begin, '\n');
	if (!p_val_end)
		return -EINVAL;

	if (p_val_end - p_val_begin > sizeof(value_str))
		return -EINVAL;

	strncpy(value_str, p_val_begin, p_val_end - p_val_begin);
	if (sscanf(value_str, "%u", value) != 1)
		return -EINVAL;

	return 0;
}


int parse_topology_device(struct tp_device *dev, unsigned gpu_id, const char* dir_path)
{
	FILE *file;
	char path[300];
	char line[300];

	dev->gpu_id = gpu_id;
	sprintf(path, "%s/properties", dir_path);
	file = fopen(path, "r");
	if (!file) {
		pr_perror("Failed to access %s\n", path);
		return -EFAULT;
	}

	/* We ignore the following entries: simd_id_base, cpu_core_id_base, location_id, max_engine_clk_fcompute,
		max_engine_clk_ccompute */

	while (fgets(line, sizeof(line), file)) {
		if (get_prop_uint32(line, "cpu_cores_count", &dev->cpu_cores_count)) goto fail;
		else if (get_prop_uint32(line, "simd_count", &dev->simd_count)) goto fail;
		else if (get_prop_uint32(line, "mem_banks_count", &dev->mem_banks_count)) goto fail;
		else if (get_prop_uint32(line, "caches_count", &dev->caches_count)) goto fail;
		else if (get_prop_uint32(line, "io_links_count", &dev->io_links_count)) goto fail;
		else if (get_prop_uint32(line, "cpu_core_id_base", &dev->cpu_core_id_base)) goto fail;
		else if (get_prop_uint32(line, "simd_id_base", &dev->simd_id_base)) goto fail;
		else if (get_prop_uint32(line, "max_waves_per_simd", &dev->max_waves_per_simd)) goto fail;
		else if (get_prop_uint32(line, "lds_size_in_kb", &dev->lds_size_in_kb)) goto fail;
		else if (get_prop_uint32(line, "gds_size_in_kb", &dev->gds_size_in_kb)) goto fail;
		else if (get_prop_uint32(line, "num_gws", &dev->num_gws)) goto fail;
		else if (get_prop_uint32(line, "wave_front_size", &dev->wave_front_size)) goto fail;
		else if (get_prop_uint32(line, "array_count", &dev->array_count)) goto fail;
		else if (get_prop_uint32(line, "simd_arrays_per_engine", &dev->simd_arrays_per_engine)) goto fail;
		else if (get_prop_uint32(line, "cu_per_simd_array", &dev->cu_per_simd_array)) goto fail;
		else if (get_prop_uint32(line, "simd_per_cu", &dev->simd_per_cu)) goto fail;
		else if (get_prop_uint32(line, "max_slots_scratch_cu", &dev->max_slots_scratch_cu)) goto fail;
		else if (get_prop_uint32(line, "vendor_id", &dev->vendor_id)) goto fail;
		else if (get_prop_uint32(line, "device_id", &dev->device_id)) goto fail;
		else if (get_prop_uint32(line, "domain", &dev->domain)) goto fail;
		else if (get_prop_uint32(line, "drm_render_minor", &dev->drm_render_minor)) goto fail;
		else if (get_prop_uint64(line, "hive_id", &dev->hive_id)) goto fail;
		else if (get_prop_uint32(line, "num_sdma_engines", &dev->num_sdma_engines)) goto fail;
		else if (get_prop_uint32(line, "num_sdma_xgmi_engines", &dev->num_sdma_xgmi_engines)) goto fail;
		else if (get_prop_uint32(line, "num_sdma_queues_per_engine", &dev->num_sdma_queues_per_engine)) goto fail;
		else if (get_prop_uint32(line, "num_cp_queues", &dev->num_cp_queues)) goto fail;
		else if (get_prop_uint64(line, "local_mem_size", &dev->local_mem_size)) goto fail;
		else if (get_prop_uint32(line, "fw_version", &dev->fw_version)) goto fail;
		else if (get_prop_uint32(line, "capability", &dev->capability)) goto fail;
		else if (get_prop_uint32(line, "sdma_fw_version", &dev->sdma_fw_version)) goto fail;
	}

	fclose(file);
	return 0;
fail:
       pr_err("Failed to parse line = %s \n", line);
       fclose(file);
       return -EINVAL;
}

int parse_topology(struct tp_system *topology)
{
	struct dirent *dirent_system;
	DIR *d_system;
	char path[300];
	int num_nodes = 0;
	int i;

	if (topology->parsed)
		return 0;

	topology->parsed = true;

	d_system = opendir(TOPOLOGY_PATH);
	if (!d_system) {
		pr_perror("Can't open %s\n", TOPOLOGY_PATH);
		return -EACCES;
	}

	while ((dirent_system = readdir(d_system)) != NULL) {
		struct stat stbuf;
		int id, fd;

		/* Only parse numeric directories */
		if (sscanf(dirent_system->d_name, "%d", &id) != 1) {
			continue;
		}

		sprintf(path, "%s/%s", TOPOLOGY_PATH, dirent_system->d_name);
		if (stat(path, &stbuf)) {
			pr_info("Cannot to access %s\n", path);
			continue;
		}

		if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
			int len;
			char gpu_id_path[300];
			char read_buf[7]; /* Max gpu_id len is 6 chars */
			unsigned gpu_id;
			sprintf(gpu_id_path, "%s/%s/gpu_id", TOPOLOGY_PATH, dirent_system->d_name);
			fd = open(gpu_id_path, O_RDONLY);
			if (fd < 0) {
				pr_perror("Failed to access %s\n", gpu_id_path);
				continue;
			}

			len = read(fd, read_buf, sizeof(read_buf));
			close(fd);
			if (len < 0)
				continue;

			if (sscanf(read_buf, "%d", &gpu_id) != 1 || !gpu_id)
				continue;

			if (topology->num_nodes + 1 >= NUM_OF_SUPPORTED_GPUS) {
				pr_err("Number of nodes exceed max supported GPU\n");
				return -EINVAL;
			}

			if (parse_topology_device(&topology->devs[num_nodes++], gpu_id, path)) {
				pr_err("Failed to parse node %s", path);
				return -EINVAL;
			}
		}
	}
	closedir(d_system);
	topology->num_nodes = num_nodes;

	pr_info("===System Topology============================================================\n");
	for (i = 0; i < topology->num_nodes; i++) {
		struct tp_device *tp_dev = &topology->devs[i];
		pr_info(" [%d] gpu_id:%x\n", i, tp_dev->gpu_id);
		pr_info("      cpu_cores_count:%u simd_count:%u mem_banks_count:%u caches_count:%d\n",
				tp_dev->cpu_cores_count, tp_dev->simd_count,
				tp_dev->mem_banks_count, tp_dev->caches_count);
		pr_info("      io_links_count:%u cpu_core_id_base:%x simd_id_base:%x\n",
				tp_dev->io_links_count, tp_dev->cpu_core_id_base,
				tp_dev->simd_id_base);
		pr_info("      max_waves_per_simd:%u lds_size_in_kb:%u gds_size_in_kb:%u\n",
				tp_dev->max_waves_per_simd, tp_dev->lds_size_in_kb,
				tp_dev->gds_size_in_kb);
		pr_info("      num_gws:%u wave_front_size:%u array_count:%u\n",
				tp_dev->num_gws, tp_dev->wave_front_size, tp_dev->array_count);
		pr_info("      simd_arrays_per_engine:%u cu_per_simd_array:%u simd_per_cu:%u\n",
				tp_dev->simd_arrays_per_engine, tp_dev->cu_per_simd_array,
				tp_dev->simd_per_cu);
		pr_info("      max_slots_scratch_cu:%u vendor_id:%u device_id:%u\n",
				tp_dev->max_slots_scratch_cu, tp_dev->vendor_id, tp_dev->device_id);
		pr_info("      domain:%u drm_render_minor:%u hive_id:%lu num_sdma_engines:%u\n",
				tp_dev->domain, tp_dev->drm_render_minor, tp_dev->hive_id,
				tp_dev->num_sdma_engines);
		pr_info("      num_sdma_xgmi_engines:%u num_sdma_queues_per_engine:%u\n",
				tp_dev->num_sdma_xgmi_engines, tp_dev->num_sdma_queues_per_engine);
		pr_info("      num_cp_queues:%u fw_version:%u\n",
				tp_dev->num_cp_queues, tp_dev->fw_version);
		pr_info("      capability:%u sdma_fw_version:%u\n",
				tp_dev->capability, tp_dev->sdma_fw_version);
	}
	pr_info("==============================================================================\n");
	return 0;
}

int get_gpu_map(struct gpu_id_maps *gpu_maps, uint32_t src, uint32_t *dest)
{
	/* If we have an existing mapping for this gpu_id, return it */
	for (int i = 0; i < gpu_maps->num_devices; i++) {
		if (gpu_maps->maps[i].src == src) {
			*dest = gpu_maps->maps[i].dest;
			return 0;
		}
	}
	pr_err("Failed to find destination GPU ID for 0x%04x (num_devices:%d)\n", src, gpu_maps->num_devices);
	return -1;
}

bool device_match(DevinfoEntry *src_dev, struct tp_device *tp_dev)
{
	if (src_dev->cpu_cores_count == tp_dev->cpu_cores_count &&
		src_dev->simd_count == tp_dev->simd_count &&
		src_dev->mem_banks_count == tp_dev->mem_banks_count &&
		src_dev->io_links_count == tp_dev->io_links_count &&
		src_dev->max_waves_per_simd == tp_dev->max_waves_per_simd &&
		src_dev->lds_size_in_kb == tp_dev->lds_size_in_kb &&
		src_dev->num_gws == tp_dev->num_gws &&
		src_dev->wave_front_size == tp_dev->wave_front_size &&
		src_dev->array_count == tp_dev->array_count &&
		src_dev->simd_arrays_per_engine == tp_dev->simd_arrays_per_engine &&
		src_dev->cu_per_simd_array == tp_dev->cu_per_simd_array &&
		src_dev->simd_per_cu == tp_dev->simd_per_cu &&
		src_dev->max_slots_scratch_cu == tp_dev->max_slots_scratch_cu &&
		src_dev->vendor_id == tp_dev->vendor_id &&
		src_dev->device_id == tp_dev->device_id &&
		src_dev->num_sdma_engines == tp_dev->num_sdma_engines &&
		src_dev->num_sdma_xgmi_engines == tp_dev->num_sdma_xgmi_engines &&
		src_dev->num_sdma_queues_per_engine == tp_dev->num_sdma_queues_per_engine &&
		src_dev->num_cp_queues == tp_dev->num_cp_queues &&
		src_dev->capability == tp_dev->capability &&
		src_dev->sdma_fw_version == tp_dev->sdma_fw_version &&
		src_dev->caches_count <= tp_dev->caches_count &&
		src_dev->fw_version <= tp_dev->fw_version) {

		return true;
	}
	return false;
}

void print_required_properties(DevinfoEntry *src_dev)
{
	pr_err("===Required properties==================================================\n");
	pr_err("      cpu_cores_count:%u simd_count:%u mem_banks_count:%u caches_count:%u\n",
			src_dev->cpu_cores_count, src_dev->simd_count,
			src_dev->mem_banks_count, src_dev->caches_count);
	pr_err("      io_links_count:%u max_waves_per_simd:%u lds_size_in_kb:%u\n",
			src_dev->io_links_count, src_dev->max_waves_per_simd,
			src_dev->lds_size_in_kb);
	pr_err("      num_gws:%u wave_front_size:%u array_count:%u\n",
			src_dev->num_gws, src_dev->wave_front_size, src_dev->array_count);
	pr_err("      simd_arrays_per_engine:%u cu_per_simd_array:%u simd_per_cu:%u\n",
			src_dev->simd_arrays_per_engine, src_dev->cu_per_simd_array,
			src_dev->simd_per_cu);
	pr_err("      max_slots_scratch_cu:%u vendor_id:%u device_id:%u\n",
			src_dev->max_slots_scratch_cu, src_dev->vendor_id, src_dev->device_id);
	pr_err("      num_sdma_engines:%u num_sdma_xgmi_engines:%u num_sdma_queues_per_engine:%u\n",
			src_dev->num_sdma_engines, src_dev->num_sdma_xgmi_engines,
			src_dev->num_sdma_queues_per_engine);
	pr_err("      num_cp_queues:%u fw_version:%u capability:%u sdma_fw_version:%u\n",
			src_dev->num_cp_queues, src_dev->fw_version, src_dev->capability,
			src_dev->sdma_fw_version);
	pr_err("========================================================================\n");
}

/* Parse local system topology and compare with checkpointed devices so we can build a set of gpu
 * maps that is used for local target gpu's */
int set_restore_gpu_maps(struct gpu_id_maps *gpu_maps, DevinfoEntry *src_devs[],
                               uint32_t num_devices, struct tp_system *topo)
{
	int i,j;
	bool matched_devices[NUM_OF_SUPPORTED_GPUS];

	if (parse_topology(topo))
		return -EFAULT;

	if (topo->num_nodes != num_devices) {
		pr_err("Number of devices mismatch (local:%d checkpointed:%d)\n",
						topo->num_nodes, num_devices);
		return -EINVAL;
	}

	memset(matched_devices, 0, sizeof(matched_devices));
	gpu_maps->num_devices = num_devices;

	for (i = 0; i < num_devices; i++) {
		for (j = 0; j < num_devices; j++) {
			if (matched_devices[j])
				continue;

			if (device_match(src_devs[i], &topo->devs[j])) {
				matched_devices[j] = true;
				gpu_maps->maps[i].src = src_devs[i]->gpu_id;
				gpu_maps->maps[i].dest = topo->devs[j].gpu_id;
				pr_info("Matched gpu 0x%04x->0x%04x\n", gpu_maps->maps[i].src,
						gpu_maps->maps[i].dest);
				break;
			}
		}

		if (j < num_devices)
			continue;

		pr_err("No matching destination GPU for gpu_id = 0x%04x\n", src_devs[i]->gpu_id);
		print_required_properties(src_devs[i]);

		return -ENOTSUP;
	}
	return 0;
}

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
		if (e->devinfo_entries[i])
			xfree(e->devinfo_entries[i]);
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
	e->devinfo_entries = xmalloc(sizeof(DevinfoEntry) * num_of_devices);
	if (!e->devinfo_entries) {
		pr_err("Failed to allocate devinfo_entries\n");
		return -1;
	}

	for (int i = 0; i < num_of_devices; i++)
	{
		DevinfoEntry *entry = xmalloc(sizeof(DevinfoEntry));
		if (!entry) {
			pr_err("Failed to allocate botest\n");
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
			pr_err("Failed to allocate botest\n");
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
int kfd_plugin_init(int stage)
{
	pr_info("kfd_plugin: initialized:  %s (AMDGPU/KFD)\n",
						CR_PLUGIN_DESC.name);

	memset(&src_topology, 0, sizeof(src_topology));
	memset(&dest_topology, 0, sizeof(dest_topology));
	memset(&checkpoint_maps, 0, sizeof(checkpoint_maps));
	memset(&restore_maps, 0, sizeof(restore_maps));
	return 0;
}

void kfd_plugin_fini(int stage, int ret)
{
	pr_info("kfd_plugin: finished  %s (AMDGPU/KFD)\n", CR_PLUGIN_DESC.name);
}

CR_PLUGIN_REGISTER("kfd_plugin", kfd_plugin_init, kfd_plugin_fini)

int kfd_plugin_dump_file(int fd, int id)
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

	printf("kfd_plugin: Enter cr_plugin_dump_file()- ID = 0x%x\n", id);
	ret = 0;
	CriuKfd *e;

	if (fstat(fd, &st) == -1) {
		pr_perror("kfd_plugin: fstat error");
		return -1;
	}

	ret = stat("/dev/kfd", &st_kfd);
	if (ret == -1) {
		pr_perror("kfd_plugin: fstat error for /dev/kfd\n");
		return -1;
	}

	if (parse_topology(&src_topology))
		return -1;

	/* Check whether this plugin was called for kfd or render nodes */
	if (major(st.st_rdev) != major(st_kfd.st_rdev) ||
		 minor(st.st_rdev) != 0) {
		/* This is RenderD dumper plugin, save the render minor and gpu_id */
		CriuRenderNode rd = CRIU_RENDER_NODE__INIT;
		struct tp_device *tp_dev;

		pr_info("kfd_plugin: Dumper called for /dev/dri/renderD%d, FD = %d, ID = %d\n",
			minor(st.st_rdev), fd, id);

		tp_dev = get_tp_device_by_render_minor(&src_topology, minor(st.st_rdev));
		if (!tp_dev) {
			pr_err("kfd_plugin: Failed to find a device with minor number = %d\n",
				minor(st.st_rdev));

			return -EFAULT;
		}

		if (get_gpu_map(&checkpoint_maps, tp_dev->gpu_id, &rd.gpu_id))
			return -EFAULT;

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

	pr_info("kfd_plugin: %s : %s() called for fd = %d\n", CR_PLUGIN_DESC.name,
		  __func__, major(st.st_rdev));

	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_HELPER, &helper_args) == -1) {
		pr_perror("kfd_plugin: failed to call helper ioctl\n");
		return -1;
	}

	args.num_of_devices = helper_args.num_of_devices;
	devinfo_bucket_ptr = xmalloc(helper_args.num_of_devices *
					sizeof(struct kfd_criu_devinfo_bucket));

	if (!devinfo_bucket_ptr) {
		pr_perror("kfd_plugin: failed to allocate devinfo for dumper ioctl\n");
		return -ENOMEM;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	pr_info("kfd_plugin: num of bos = %llu\n", helper_args.num_of_bos);

	bo_bucket_ptr = xmalloc(helper_args.num_of_bos *
			       sizeof(struct kfd_criu_bo_buckets));

	if (!bo_bucket_ptr) {
		pr_perror("kfd_plugin: failed to allocate args for dumper ioctl\n");
		return -ENOMEM;
	}

	args.num_of_bos = helper_args.num_of_bos;
	args.kfd_criu_bo_buckets_ptr = (uintptr_t)bo_bucket_ptr;

	pr_info("kfd_plugin: num of queues = %u\n", helper_args.num_of_queues);

	q_bucket_ptr = xmalloc(helper_args.num_of_queues *
			       sizeof(struct kfd_criu_q_bucket));

	if (!q_bucket_ptr) {
		pr_perror("kfd_plugin: failed to allocate args for dumper ioctl\n");
		return -1;
	}

	args.num_of_queues = helper_args.num_of_queues;
	args.kfd_criu_q_buckets_ptr = (uintptr_t)q_bucket_ptr;

	if (helper_args.queues_data_size) {
		args.queues_data_ptr = (uintptr_t)xmalloc(helper_args.queues_data_size);
		if (!args.queues_data_ptr) {
			pr_perror("kfd_plugin: failed to allocate args for dumper ioctl\n");
			return -1;
		}
		args.queues_data_size = helper_args.queues_data_size;
		pr_info("kfd_plugin: queues data size:%llu\n", args.queues_data_size);
	}

	if (helper_args.num_of_events) {
		ev_buckets_ptr = xmalloc(helper_args.num_of_events *
					sizeof(struct kfd_criu_ev_bucket));
		args.num_of_events = helper_args.num_of_events;
	}

	args.kfd_criu_ev_buckets_ptr = (uintptr_t)ev_buckets_ptr;

	/* call dumper ioctl, pass num of BOs to dump */
        if (kmtIoctl(fd, AMDKFD_IOC_CRIU_DUMPER, &args) == -1) {
		pr_perror("kfd_plugin: failed to call kfd ioctl from plugin dumper for fd = %d\n", major(st.st_rdev));
		xfree(bo_bucket_ptr);
		return -1;
	}

	pr_info("kfd_plugin: success in calling dumper ioctl\n");

	e = xmalloc(sizeof(*e));
	if (!e) {
		pr_err("Failed to allocate proto structure\n");
		xfree(bo_bucket_ptr);
		return -ENOMEM;
	}

	criu_kfd__init(e);
	e->pid = helper_args.task_pid;

	ret = allocate_devinfo_entries(e, args.num_of_devices);
	if (ret) {
		ret = -ENOMEM;
		goto failed;
	}

	/* When checkpointing on a node where there was already a checkpoint-restore before, the
	 * user_gpu_id and actual_gpu_id will be different.
	 *
	 * We store the user_gpu_id in the stored image files so that the stored images always have
	 * the gpu_id's of the node where the application was first launched. */

	checkpoint_maps.num_devices = args.num_of_devices;
	for (int i = 0; i < args.num_of_devices; i++) {
		checkpoint_maps.maps[i].src = devinfo_bucket_ptr[i].actual_gpu_id;
		checkpoint_maps.maps[i].dest = devinfo_bucket_ptr[i].user_gpu_id;
	}

	/* Store local topology information */
	for (int i = 0; i < args.num_of_devices; i++) {
		struct tp_device *dev;

		dev = get_tp_device_by_gpu_id(&src_topology, devinfo_bucket_ptr[i].actual_gpu_id);
		if (!dev) {
			ret = -EFAULT;
			goto failed;
		}

		e->devinfo_entries[i]->gpu_id = devinfo_bucket_ptr[i].user_gpu_id;

		e->devinfo_entries[i]->cpu_cores_count = dev->cpu_cores_count;
		e->devinfo_entries[i]->simd_count = dev->simd_count;
		e->devinfo_entries[i]->mem_banks_count = dev->mem_banks_count;
		e->devinfo_entries[i]->caches_count = dev->caches_count;
		e->devinfo_entries[i]->io_links_count = dev->io_links_count;
		e->devinfo_entries[i]->simd_id_base = dev->simd_id_base;
		e->devinfo_entries[i]->max_waves_per_simd = dev->max_waves_per_simd;
		e->devinfo_entries[i]->lds_size_in_kb = dev->lds_size_in_kb;
		e->devinfo_entries[i]->num_gws = dev->num_gws;
		e->devinfo_entries[i]->wave_front_size = dev->wave_front_size;
		e->devinfo_entries[i]->array_count = dev->array_count;
		e->devinfo_entries[i]->simd_arrays_per_engine = dev->simd_arrays_per_engine;
		e->devinfo_entries[i]->cu_per_simd_array = dev->cu_per_simd_array;
		e->devinfo_entries[i]->simd_per_cu = dev->simd_per_cu;
		e->devinfo_entries[i]->max_slots_scratch_cu = dev->max_slots_scratch_cu;
		e->devinfo_entries[i]->vendor_id = dev->vendor_id;
		e->devinfo_entries[i]->device_id = dev->device_id;
		e->devinfo_entries[i]->domain = dev->domain;
		e->devinfo_entries[i]->drm_render_minor = dev->drm_render_minor;
		e->devinfo_entries[i]->hive_id = dev->hive_id;
		e->devinfo_entries[i]->num_sdma_engines = dev->num_sdma_engines;
		e->devinfo_entries[i]->num_sdma_xgmi_engines = dev->num_sdma_xgmi_engines;
		e->devinfo_entries[i]->num_sdma_queues_per_engine = dev->num_sdma_queues_per_engine;
		e->devinfo_entries[i]->num_cp_queues = dev->num_cp_queues;
		e->devinfo_entries[i]->local_mem_size = dev->local_mem_size;
		e->devinfo_entries[i]->fw_version = dev->fw_version;
		e->devinfo_entries[i]->capability = dev->capability;
		e->devinfo_entries[i]->sdma_fw_version = dev->sdma_fw_version;
	}

	e->num_of_devices = args.num_of_devices;

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

		if (get_gpu_map(&checkpoint_maps, bo_bucket_ptr[i].gpu_id,
			&e->bo_info_test[i]->gpu_id)) {
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
				struct tp_device *dev;

				plugin_log_msg("kfd_plugin: large bar read possible\n");

				dev = get_tp_device_by_gpu_id(&src_topology, bo_bucket_ptr[i].gpu_id);
				if (!dev) {
					ret = -EFAULT;
					goto failed;
				}

				drm_fd = open_drm_render_device(dev->drm_render_minor);
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
					pr_perror("kfd_plugin: mmap failed\n");
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

		if (get_gpu_map(&checkpoint_maps, q_bucket_ptr[i].gpu_id,
				&e->q_entries[i]->gpu_id)) {

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
	pr_info("kfd_plugin: number of events:%d\n", args.num_of_events);

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
					if (get_gpu_map(&checkpoint_maps,
							ev_buckets_ptr[i].memory_exception_data.gpu_id,
							&e->ev_entries[i]->mem_exc_gpu_id)) {
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
					if (get_gpu_map(&checkpoint_maps,
							ev_buckets_ptr[i].hw_exception_data.gpu_id,
							&e->ev_entries[i]->hw_exc_gpu_id)) {
						ret = -EFAULT;
						goto failed;
					}
				}
			}
		}
	}

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);
	pr_info("kfd_plugin: img_path = %s", img_path);

	len = criu_kfd__get_packed_size(e);

	pr_info("kfd_plugin: Len = %ld\n", len);

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
	pr_info("kfd_plugin: Exiting from dumper for fd = %d\n", major(st.st_rdev));
        return ret;

}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, kfd_plugin_dump_file)

int kfd_plugin_restore_file(int id)
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

	pr_info("kfd_plugin: Initialized kfd plugin restorer with ID = %d\n", id);

	snprintf(img_path, sizeof(img_path), "kfd.%d.img", id);

	if (stat(img_path, &filestat) == -1) {
		struct tp_device *tp_dev;
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

		pr_info("kfd_plugin: render node gpu_id = 0x%04x\n", rd->gpu_id);

		if (get_gpu_map(&restore_maps, rd->gpu_id, &target_gpu_id)) {
			fd = -EBADFD;
			goto fail;
		}

		tp_dev = get_tp_device_by_gpu_id(&dest_topology, target_gpu_id);
		if (!tp_dev) {
			fd = -EBADFD;
			goto fail;
		}

		pr_info("kfd_plugin: render node destination gpu_id = 0x%04x\n", tp_dev->gpu_id);

		fd = open_drm_render_device(tp_dev->drm_render_minor);
		if (fd < 0)
			pr_err("kfd_plugin: Failed to open render device (minor:%d)\n",
									tp_dev->drm_render_minor);
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
	pr_info("kfd_plugin: Opened kfd, fd = %d\n", fd);
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
		pr_err("Unable to parse the KFD message %#x", id);
		xfree(buf);
		return -1;
	}

	plugin_log_msg("kfd_plugin: read image file data\n");

	args.num_of_devices = e->num_of_devices;

	devinfo_bucket_ptr = xmalloc(e->num_of_devices * sizeof(struct kfd_criu_devinfo_bucket));
	if (!devinfo_bucket_ptr) {
		fd = -EBADFD;
		goto clean;
	}
	args.kfd_criu_devinfo_buckets_ptr = (uintptr_t)devinfo_bucket_ptr;

	/* set_restore_gpu_maps will parse local topology and fill dest_topology */
	if (set_restore_gpu_maps(&restore_maps, e->devinfo_entries, e->num_of_devices, &dest_topology)) {
		fd = -EBADFD;
		goto clean;
	}

	for (int i = 0; i < e->num_of_devices; i++) {
		struct tp_device *tp_dev;
		int drm_fd;
		devinfo_bucket_ptr[i].user_gpu_id = e->devinfo_entries[i]->gpu_id;

		if (get_gpu_map(&restore_maps, e->devinfo_entries[i]->gpu_id,
			&devinfo_bucket_ptr[i].actual_gpu_id)) {

			fd = -EBADFD;
			goto clean;
		}

		tp_dev = get_tp_device_by_gpu_id(&dest_topology,
							devinfo_bucket_ptr[i].actual_gpu_id);
		if (!tp_dev) {
			fd = -EBADFD;
			goto clean;
		}
		drm_fd = open_drm_render_device(tp_dev->drm_render_minor);
		if (drm_fd < 0) {
			fd = -EBADFD;
			goto clean;
		}
		devinfo_bucket_ptr[i].drm_fd = drm_fd;
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
		pr_perror("kfd_plugin: failed to allocate args for restorer ioctl\n");
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

		if (get_gpu_map(&restore_maps, e->bo_info_test[i]->gpu_id,
						&bo_bucket_ptr[i].gpu_id)) {
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
               pr_perror("kfd_plugin: failed to allocate args for dumper ioctl\n");
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
		pr_perror("kfd_plugin: failed to allocate args for dumper ioctl\n");
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

		if (get_gpu_map(&restore_maps, e->q_entries[i]->gpu_id, &q_bucket_ptr[i].gpu_id)) {
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
			pr_perror("kfd_plugin: failed to allocate events for restore ioctl\n");
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
					if (get_gpu_map(&restore_maps, e->ev_entries[i]->mem_exc_gpu_id,
							&ev_bucket_ptr[i].memory_exception_data.gpu_id)) {

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
					if (get_gpu_map(&restore_maps, e->ev_entries[i]->hw_exc_gpu_id,
							&ev_bucket_ptr[i].hw_exception_data.gpu_id)) {
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
		pr_perror("kfd_plugin: failed to call kfd ioctl from plugin restorer for id = %d\n", id);
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

			struct tp_device *tp_dev;
			struct vma_metadata *vma_md;
			vma_md = xmalloc(sizeof(*vma_md));
			if (!vma_md)
				return -ENOMEM;

			memset(vma_md, 0, sizeof(*vma_md));

			vma_md->old_pgoff = bo_bucket_ptr[i].bo_offset;
			vma_md->vma_entry = bo_bucket_ptr[i].bo_addr;

			tp_dev = get_tp_device_by_gpu_id(&dest_topology, bo_bucket_ptr[i].gpu_id);
			vma_md->new_minor = tp_dev->drm_render_minor;

			vma_md->new_pgoff = restored_bo_offsets_array[i];

			plugin_log_msg("kfd_plugin: adding vma_entry:addr:0x%lx old-off:0x%lx \
					new_off:0x%lx new_minor:%d\n", vma_md->vma_entry,
					vma_md->old_pgoff, vma_md->new_pgoff, vma_md->new_minor);

			list_add_tail(&vma_md->list, &update_vma_info_list);
		}

		if (e->bo_info_test[i]->bo_alloc_flags &
			(KFD_IOC_ALLOC_MEM_FLAGS_VRAM | KFD_IOC_ALLOC_MEM_FLAGS_GTT)) {

			int j;
			int drm_render_fd = -EBADFD;

			for (j = 0; j < e->num_of_devices; j++) {
				if (devinfo_bucket_ptr[j].actual_gpu_id == bo_bucket_ptr[i].gpu_id) {
					drm_render_fd = devinfo_bucket_ptr[j].drm_fd;
					break;
				}
			}

			if (drm_render_fd < 0) {
				pr_err("kfd_plugin: bad fd for render node\n");
				fd = -EBADFD;
				goto clean;
			}

			plugin_log_msg("kfd_plugin: Trying mmap in stage 2\n");
			if ((e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC ||
			    (e->bo_info_test[i])->bo_alloc_flags &
			    KFD_IOC_ALLOC_MEM_FLAGS_GTT ) {
				plugin_log_msg("kfd_plugin: large bar write possible\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_WRITE,
					    MAP_SHARED,
					    drm_render_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("kfd_plugin: mmap failed\n");
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
				plugin_log_msg("kfd_plugin: using PROCPIDMEM to restore BO contents\n");
				addr = mmap(NULL,
					    (e->bo_info_test[i])->bo_size,
					    PROT_NONE,
					    MAP_SHARED,
					    drm_render_fd,
					    restored_bo_offsets_array[i]);
				if (addr == MAP_FAILED) {
					pr_perror("kfd_plugin: mmap failed\n");
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

	for (int i = 0; i < e->num_of_devices; i++) {
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
	pr_info("kfd_plugin: returning kfd fd from plugin, fd = %d\n", fd);
	return fd;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, kfd_plugin_restore_file)

/* return 0 if no match found
 * return -1 for error.
 * return 1 if vmap map must be adjusted. */
int kfd_plugin_update_vmamap(const char *old_path, char *new_path, const uint64_t addr,
				const uint64_t old_offset, uint64_t *new_offset)
{
	struct vma_metadata *vma_md;
	char path[PATH_MAX];
	char *p_begin;
	char *p_end;
	bool is_kfd = false, is_renderD = false;


	pr_info("kfd_plugin: Enter %s\n", __func__);

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

			pr_info("kfd_plugin: old_pgoff= 0x%lx new_pgoff = 0x%lx old_path = %s new_path = %s\n",
				vma_md->old_pgoff, vma_md->new_pgoff, old_path, new_path);

			return 1;
		}
	}
	pr_info("No match for addr:0x%lx offset:%lx\n", addr, old_offset);
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, kfd_plugin_update_vmamap)

int kfd_plugin_resume_devices_late(int target_pid)
{
	struct kfd_ioctl_criu_resume_args args = {0};
	int fd, ret = 0;

	pr_info("kfd_plugin: Inside %s for target pid = %d\n", __func__, target_pid);

	fd = open("/dev/kfd", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open kfd in plugin");
		return -1;
	}

	args.pid = target_pid;
	pr_info("kfd_plugin: Calling IOCTL to start notifiers and queues\n");
	if (kmtIoctl(fd, AMDKFD_IOC_CRIU_RESUME, &args) == -1) {
		pr_perror("restore late ioctl failed\n");
		ret = -1;
	}

	close(fd);
	return ret;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, kfd_plugin_resume_devices_late)
