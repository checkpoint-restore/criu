
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#include <dirent.h>
#include "common/list.h"

#include "xmalloc.h"
#include "kfd_ioctl.h"
#include "amdgpu_plugin_topology.h"

#define TOPOLOGY_PATH "/sys/class/kfd/kfd/topology/nodes/"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef COMPILE_TESTS
#undef pr_err
#define pr_err(format, arg...) fprintf(stdout, "%s:%d ERROR:" format, __FILE__, __LINE__, ##arg)
#undef pr_info
#define pr_info(format, arg...) fprintf(stdout, "%s:%d INFO:" format, __FILE__, __LINE__, ##arg)
#undef pr_debug
#define pr_debug(format, arg...) fprintf(stdout, "%s:%d DBG:" format, __FILE__, __LINE__, ##arg)

#undef pr_perror
#define pr_perror(format, arg...) \
	fprintf(stdout, "%s:%d: " format " (errno = %d (%s))\n", __FILE__, __LINE__, ##arg, errno, strerror(errno))
#endif

#ifdef DEBUG
#define plugin_log_msg(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
#define plugin_log_msg(fmt, ...) \
	{                        \
	}
#endif

/* User override options */
/* Skip firmware version check */
bool kfd_fw_version_check = true;
/* Skip SDMA firmware version check */
bool kfd_sdma_fw_version_check = true;
/* Skip caches count check */
bool kfd_caches_count_check = true;
/* Skip num gws check */
bool kfd_num_gws_check = true;
/* Skip vram size check */
bool kfd_vram_size_check = true;
/* Preserve NUMA regions */
bool kfd_numa_check = true;
/* Skip capability check */
bool kfd_capability_check = true;

/*
 * During dump, we can use any fd value so fd_next is always -1.
 * During restore, we have to use a fd value that does not conflict with fd values in use by the target restore process.
 * fd_next is initialized as 1 greater than the highest-numbered file descriptor used by the target restore process.
 */
int fd_next = -1;

static int open_drm_render_device(int minor)
{
	char path[128];
	int fd, ret_fd;

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

	if (fd_next < 0)
		return fd;

	ret_fd = fcntl(fd, F_DUPFD, fd_next++);
	close(fd);

	if (ret_fd < 0)
		pr_perror("Failed to duplicate fd for minor:%d (fd_next:%d)", minor, fd_next);

	return ret_fd;
}

static const char *link_type(uint32_t type)
{
	switch (type) {
	case TOPO_IOLINK_TYPE_PCIE:
		return "PCIe";
	case TOPO_IOLINK_TYPE_XGMI:
		return "XGMI";
	}
	return "Unsupported";
}

static struct tp_node *p2pgroup_get_node_by_gpu_id(const struct tp_p2pgroup *group, const uint32_t gpu_id)
{
	struct tp_node *node;

	list_for_each_entry(node, &group->nodes, listm_p2pgroup) {
		if (node->gpu_id == gpu_id)
			return node;
	}
	return NULL;
}

int node_get_drm_render_device(struct tp_node *node)
{
	if (node->drm_fd < 0)
		node->drm_fd = open_drm_render_device(node->drm_render_minor);

	return node->drm_fd;
}

void sys_close_drm_render_devices(struct tp_system *sys)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (node->drm_fd >= 0) {
			close(node->drm_fd);
			node->drm_fd = -1;
		}
	}
}

static struct tp_iolink *node_get_iolink_to_node_id(const struct tp_node *node, const uint32_t type,
						    const uint32_t node_id)
{
	struct tp_iolink *iolink;

	list_for_each_entry(iolink, &node->iolinks, listm) {
		if (iolink->node_to_id == node_id && iolink->type == type)
			return iolink;
	}
	return NULL;
}

struct tp_node *sys_get_node_by_render_minor(const struct tp_system *sys, const int drm_render_minor)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (node->drm_render_minor == drm_render_minor)
			return node;
	}
	return NULL;
}

struct tp_node *sys_get_node_by_index(const struct tp_system *sys, uint32_t index)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (NODE_IS_GPU(node) && index-- == 0)
			return node;
	}
	return NULL;
}

struct tp_node *sys_get_node_by_gpu_id(const struct tp_system *sys, const uint32_t gpu_id)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (node->gpu_id == gpu_id)
			return node;
	}
	return NULL;
}

static struct tp_node *sys_get_node_by_node_id(const struct tp_system *sys, const uint32_t node_id)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (node->id == node_id)
			return node;
	}
	return NULL;
}

static struct tp_p2pgroup *sys_get_p2pgroup_with_gpu_id(const struct tp_system *sys, const int type,
							const uint32_t gpu_id)
{
	struct tp_p2pgroup *p2pgroup;

	list_for_each_entry(p2pgroup, &sys->xgmi_groups, listm_system) {
		if (p2pgroup->type != type)
			continue;

		if (p2pgroup_get_node_by_gpu_id(p2pgroup, gpu_id))
			return p2pgroup;
	}
	return NULL;
}

static struct tp_iolink *get_tp_peer_iolink(const struct tp_node *from_node, const struct tp_node *to_node,
					    const uint8_t type)
{
	struct tp_iolink *iolink;

	list_for_each_entry(iolink, &from_node->iolinks, listm) {
		if (iolink->node_to_id == to_node->id && iolink->type == type)
			return iolink;
	}
	return NULL;
}

static bool maps_dest_cpu_mapped(const struct device_maps *maps, const uint32_t dest_id)
{
	struct id_map *id_map;

	list_for_each_entry(id_map, &maps->cpu_maps, listm) {
		if (id_map->dest == dest_id)
			return true;
	}
	return false;
}

static uint32_t maps_get_dest_cpu(const struct device_maps *maps, const uint32_t src_id)
{
	struct id_map *id_map;

	list_for_each_entry(id_map, &maps->cpu_maps, listm) {
		if (id_map->src == src_id)
			return id_map->dest;
	}
	return INVALID_CPU_ID;
}

bool maps_dest_gpu_mapped(const struct device_maps *maps, const uint32_t dest_id)
{
	struct id_map *id_map;

	list_for_each_entry(id_map, &maps->gpu_maps, listm) {
		if (id_map->dest == dest_id)
			return true;
	}
	return false;
}

uint32_t maps_get_dest_gpu(const struct device_maps *maps, const uint32_t src_id)
{
	struct id_map *id_map;

	list_for_each_entry(id_map, &maps->gpu_maps, listm) {
		if (id_map->src == src_id)
			return id_map->dest;
	}
	return 0;
}

static struct id_map *maps_add_cpu_entry(struct device_maps *maps, const uint32_t src_id, const uint32_t dest_id)
{
	struct id_map *id_map = xzalloc(sizeof(*id_map));

	if (!id_map) {
		pr_err("Failed to allocate memory for id_map\n");
		return NULL;
	}

	id_map->src = src_id;
	id_map->dest = dest_id;

	list_add_tail(&id_map->listm, &maps->cpu_maps);

	maps->tail_cpu = &id_map->listm;

	pr_debug("Added CPU mapping [%02d -> %02d]\n", src_id, dest_id);
	return id_map;
}

struct id_map *maps_add_gpu_entry(struct device_maps *maps, const uint32_t src_id, const uint32_t dest_id)
{
	struct id_map *id_map = xzalloc(sizeof(*id_map));

	if (!id_map) {
		pr_err("Failed to allocate memory for id_map\n");
		return NULL;
	}

	id_map->src = src_id;
	id_map->dest = dest_id;

	list_add_tail(&id_map->listm, &maps->gpu_maps);

	maps->tail_gpu = &id_map->listm;

	pr_debug("Added GPU mapping [0x%04X -> 0x%04X]\n", src_id, dest_id);
	return id_map;
}

static void maps_print(struct device_maps *maps)
{
	struct id_map *id_map;

	pr_info("===Maps===============\n");
	list_for_each_entry(id_map, &maps->gpu_maps, listm)
		pr_info("GPU: 0x%04X -> 0x%04X\n", id_map->src, id_map->dest);

	list_for_each_entry(id_map, &maps->cpu_maps, listm)
		pr_info("CPU: %02d -> %02d\n", id_map->src, id_map->dest);
	pr_info("======================\n");
}

void maps_init(struct device_maps *maps)
{
	INIT_LIST_HEAD(&maps->cpu_maps);
	INIT_LIST_HEAD(&maps->gpu_maps);
	maps->tail_cpu = 0;
	maps->tail_gpu = 0;
}

void maps_free(struct device_maps *maps)
{
	while (!list_empty(&maps->cpu_maps)) {
		struct id_map *map = list_first_entry(&maps->cpu_maps, struct id_map, listm);

		list_del(&map->listm);
		xfree(map);
	}
	while (!list_empty(&maps->gpu_maps)) {
		struct id_map *map = list_first_entry(&maps->gpu_maps, struct id_map, listm);

		list_del(&map->listm);
		xfree(map);
	}
}

static void maps_pop(struct device_maps *maps, struct device_maps *remove)
{
	if (remove->tail_cpu)
		list_cut_position(&remove->cpu_maps, &maps->cpu_maps, remove->tail_cpu);

	if (remove->tail_gpu)
		list_cut_position(&remove->gpu_maps, &maps->gpu_maps, remove->tail_gpu);

	maps_free(remove);
}

static int maps_push(struct device_maps *maps, struct device_maps *new)
{
	struct id_map *src_id_map, *dest_id_map;

	list_for_each_entry(src_id_map, &new->cpu_maps, listm) {
		list_for_each_entry(dest_id_map, &maps->cpu_maps, listm) {
			if (src_id_map->src == dest_id_map->src || src_id_map->dest == dest_id_map->dest) {
				pr_err("CPU mapping already exists src [%02d->%02d] new [%02d->%02d]\n",
				       src_id_map->src, src_id_map->dest, dest_id_map->src, dest_id_map->dest);
				return -EINVAL;
			}
		}
	}
	list_for_each_entry(src_id_map, &new->gpu_maps, listm) {
		list_for_each_entry(dest_id_map, &maps->gpu_maps, listm) {
			if (src_id_map->src == dest_id_map->src || src_id_map->dest == dest_id_map->dest) {
				pr_err("GPU mapping already exists src [0x%04X -> 0x%04X] new [0x%04X -> 0x%04X]\n",
				       src_id_map->src, src_id_map->dest, dest_id_map->src, dest_id_map->dest);
				return -EINVAL;
			}
		}
	}

	list_splice(&new->cpu_maps, &maps->cpu_maps);
	list_splice(&new->gpu_maps, &maps->gpu_maps);

	return 0;
}

struct tp_iolink *node_add_iolink(struct tp_node *node, uint32_t type, uint32_t node_to_id)
{
	struct tp_iolink *iolink = xzalloc(sizeof(*iolink));

	if (!iolink)
		return NULL;

	iolink->type = type;
	/* iolink->node_to will be filled in topology_determine_iolinks */
	iolink->node_to_id = node_to_id;
	iolink->node_from = node;

	list_add_tail(&iolink->listm, &node->iolinks);
	return iolink;
}

struct tp_p2pgroup *sys_add_group(struct tp_system *sys, uint32_t type)
{
	struct tp_p2pgroup *group;

	group = xzalloc(sizeof(*group));
	if (!group)
		return NULL;

	INIT_LIST_HEAD(&group->nodes);
	group->type = type;
	list_add_tail(&group->listm_system, &sys->xgmi_groups);
	if (type == TOPO_IOLINK_TYPE_XGMI)
		sys->num_xgmi_groups++;

	return group;
}

struct tp_node *sys_add_node(struct tp_system *sys, uint32_t id, uint32_t gpu_id)
{
	struct tp_node *node = NULL;

	node = xzalloc(sizeof(*node));
	if (!node)
		return NULL;

	node->id = id;
	node->gpu_id = gpu_id;
	node->drm_fd = -1;
	INIT_LIST_HEAD(&node->iolinks);
	list_add_tail(&node->listm_system, &sys->nodes);
	sys->num_nodes++;

	return node;
}

static bool get_prop(char *line, char *name, uint64_t *value)
{
	if (sscanf(line, " %29s %lu", name, value) != 2)
		return false;
	return true;
}

/* Parse node properties in /sys/class/kfd/kfd/topology/nodes/N/properties */
static int parse_topo_node_properties(struct tp_node *dev, const char *dir_path)
{
	FILE *file;
	char path[300];
	char line[300];

	sprintf(path, "%s/properties", dir_path);
	file = fopen(path, "r");
	if (!file) {
		pr_perror("Failed to access %s", path);
		return -EFAULT;
	}

	while (fgets(line, sizeof(line), file)) {
		char name[30];
		uint64_t value;

		memset(name, 0, sizeof(name));
		if (!get_prop(line, name, &value))
			goto fail;

		if (!strcmp(name, "cpu_cores_count"))
			dev->cpu_cores_count = (uint32_t)value;
		else if (!strcmp(name, "simd_count"))
			dev->simd_count = (uint32_t)value;
		else if (!strcmp(name, "mem_banks_count"))
			dev->mem_banks_count = (uint32_t)value;
		else if (!strcmp(name, "caches_count"))
			dev->caches_count = (uint32_t)value;
		else if (!strcmp(name, "io_links_count"))
			dev->io_links_count = (uint32_t)value;
		else if (!strcmp(name, "max_waves_per_simd"))
			dev->max_waves_per_simd = (uint32_t)value;
		else if (!strcmp(name, "lds_size_in_kb"))
			dev->lds_size_in_kb = (uint32_t)value;
		else if (!strcmp(name, "num_gws"))
			dev->num_gws = (uint32_t)value;
		else if (!strcmp(name, "wave_front_size"))
			dev->wave_front_size = (uint32_t)value;
		else if (!strcmp(name, "array_count"))
			dev->array_count = (uint32_t)value;
		else if (!strcmp(name, "simd_arrays_per_engine"))
			dev->simd_arrays_per_engine = (uint32_t)value;
		else if (!strcmp(name, "cu_per_simd_array"))
			dev->cu_per_simd_array = (uint32_t)value;
		else if (!strcmp(name, "simd_per_cu"))
			dev->simd_per_cu = (uint32_t)value;
		else if (!strcmp(name, "max_slots_scratch_cu"))
			dev->max_slots_scratch_cu = (uint32_t)value;
		else if (!strcmp(name, "vendor_id"))
			dev->vendor_id = (uint32_t)value;
		else if (!strcmp(name, "device_id"))
			dev->device_id = (uint32_t)value;
		else if (!strcmp(name, "domain"))
			dev->domain = (uint32_t)value;
		else if (!strcmp(name, "drm_render_minor"))
			dev->drm_render_minor = (uint32_t)value;
		else if (!strcmp(name, "hive_id"))
			dev->hive_id = value;
		else if (!strcmp(name, "num_sdma_engines"))
			dev->num_sdma_engines = (uint32_t)value;
		else if (!strcmp(name, "num_sdma_xgmi_engines"))
			dev->num_sdma_xgmi_engines = (uint32_t)value;
		else if (!strcmp(name, "num_sdma_queues_per_engine"))
			dev->num_sdma_queues_per_engine = (uint32_t)value;
		else if (!strcmp(name, "num_cp_queues"))
			dev->num_cp_queues = (uint32_t)value;
		else if (!strcmp(name, "fw_version"))
			dev->fw_version = (uint32_t)value;
		else if (!strcmp(name, "capability"))
			dev->capability = (uint32_t)value;
		else if (!strcmp(name, "sdma_fw_version"))
			dev->sdma_fw_version = (uint32_t)value;

		if (!dev->gpu_id && dev->cpu_cores_count >= 1) {
			/* This is a CPU - we do not need to parse the other information */
			break;
		}
	}

	fclose(file);
	return 0;
fail:
	pr_err("Failed to parse line = %s\n", line);
	fclose(file);
	return -EINVAL;
}

/* Parse node memory properties in /sys/class/kfd/kfd/topology/nodes/N/mem_banks */
static int parse_topo_node_mem_banks(struct tp_node *node, const char *dir_path)
{
	struct dirent *dirent_node;
	DIR *d_node;
	char path[300];
	FILE *file = NULL;
	uint32_t heap_type = 0;
	uint64_t mem_size = 0;
	int ret;

	if (!NODE_IS_GPU(node))
		return 0;

	sprintf(path, "%s/mem_banks", dir_path);

	d_node = opendir(path);
	if (!d_node) {
		pr_perror("Can't open %s", path);
		return -EACCES;
	}

	while ((dirent_node = readdir(d_node)) != NULL) {
		char line[300];
		char bank_path[1024];
		struct stat st;
		int id;

		heap_type = 0;
		mem_size = 0;

		/* Only parse numeric directories */
		if (sscanf(dirent_node->d_name, "%d", &id) != 1)
			continue;

		snprintf(bank_path, sizeof(bank_path), "%s/%s", path, dirent_node->d_name);
		if (stat(bank_path, &st)) {
			pr_err("Cannot to access %s\n", path);
			ret = -EACCES;
			goto fail;
		}
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			char properties_path[PATH_MAX];

			snprintf(properties_path, sizeof(properties_path), "%s/properties", bank_path);

			file = fopen(properties_path, "r");
			if (!file) {
				pr_perror("Failed to access %s", properties_path);
				ret = -EACCES;
				goto fail;
			}

			while (fgets(line, sizeof(line), file)) {
				char name[30];
				uint64_t value;

				memset(name, 0, sizeof(name));
				if (!get_prop(line, name, &value)) {
					ret = -EINVAL;
					goto fail;
				}

				if (!strcmp(name, "heap_type"))
					heap_type = (uint32_t)value;
				if (!strcmp(name, "size_in_bytes"))
					mem_size = value;
			}

			fclose(file);
			file = NULL;
		}

		if (heap_type == TOPO_HEAP_TYPE_PUBLIC || heap_type == TOPO_HEAP_TYPE_PRIVATE)
			break;
	}

	if ((heap_type != TOPO_HEAP_TYPE_PUBLIC && heap_type != TOPO_HEAP_TYPE_PRIVATE) || !mem_size) {
		pr_err("Failed to determine memory type and size for device in %s\n", dir_path);
		ret = -EINVAL;
		goto fail;
	}

	node->vram_public = (heap_type == TOPO_HEAP_TYPE_PUBLIC);
	node->vram_size = mem_size;
	closedir(d_node);
	return 0;
fail:
	if (file)
		fclose(file);
	closedir(d_node);
	return ret;
}

/* Parse node iolinks properties in /sys/class/kfd/kfd/topology/nodes/N/io_links */
static int parse_topo_node_iolinks(struct tp_node *node, const char *dir_path)
{
	struct dirent *dirent_node;
	DIR *d_node;
	char path[300];
	FILE *file = NULL;
	int ret = 0;

	snprintf(path, sizeof(path), "%s/io_links", dir_path);

	d_node = opendir(path);
	if (!d_node) {
		pr_perror("Can't open %s", path);
		return -EACCES;
	}

	while ((dirent_node = readdir(d_node)) != NULL) {
		char line[300];
		char iolink_path[1024];
		struct stat st;
		int id;

		uint32_t iolink_type = 0;
		uint32_t node_to_id = 0;

		/* Only parse numeric directories */
		if (sscanf(dirent_node->d_name, "%d", &id) != 1)
			continue;

		snprintf(iolink_path, sizeof(iolink_path), "%s/%s", path, dirent_node->d_name);
		if (stat(iolink_path, &st)) {
			pr_err("Cannot to access %s\n", path);
			ret = -EACCES;
			goto fail;
		}
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			char properties_path[PATH_MAX];

			snprintf(properties_path, sizeof(properties_path), "%s/properties", iolink_path);

			file = fopen(properties_path, "r");
			if (!file) {
				pr_perror("Failed to access %s", properties_path);
				ret = -EACCES;
				goto fail;
			}

			while (fgets(line, sizeof(line), file)) {
				char name[30];
				uint64_t value;

				memset(name, 0, sizeof(name));
				if (!get_prop(line, name, &value)) {
					ret = -EINVAL;
					goto fail;
				}

				if (!strcmp(name, "type"))
					iolink_type = (uint32_t)value;
				if (!strcmp(name, "node_to"))
					node_to_id = (uint32_t)value;
			}
			fclose(file);
			file = NULL;
		}

		/* We only store the link information for now, then once all topology parsing is
		 * finished we will confirm iolinks
		 */
		if (iolink_type == TOPO_IOLINK_TYPE_PCIE || iolink_type == TOPO_IOLINK_TYPE_XGMI) {
			if (!node_add_iolink(node, iolink_type, node_to_id)) {
				ret = -ENOMEM;
				goto fail;
			}
		}
	}
	closedir(d_node);
	return 0;
fail:
	if (file)
		fclose(file);

	closedir(d_node);
	return ret;
}

/* Parse a node (CPU or GPU) in /sys/class/kfd/kfd/topology/nodes/N */
static int parse_topo_node(struct tp_node *node, const char *dir_path)
{
	if (parse_topo_node_properties(node, dir_path)) {
		pr_err("Failed to parse node properties\n");
		return -EINVAL;
	}
	if (parse_topo_node_mem_banks(node, dir_path)) {
		pr_err("Failed to parse node mem_banks\n");
		return -EINVAL;
	}
	if (parse_topo_node_iolinks(node, dir_path)) {
		pr_err("Failed to parse node iolinks\n");
		return -EINVAL;
	}
	return 0;
}

static const char *p2pgroup_to_str(struct tp_p2pgroup *group)
{
	static char topology_printstr[200];
	struct tp_node *node;
	size_t str_len = 0;

	topology_printstr[0] = '\0';
	str_len += sprintf(&topology_printstr[str_len], "type:%s:", link_type(group->type));

	list_for_each_entry(node, &group->nodes, listm_p2pgroup) {
		str_len += sprintf(&topology_printstr[str_len], "0x%04X ", node->gpu_id);
	}
	return topology_printstr;
}

static const char *mapping_list_to_str(struct list_head *node_list)
{
	static char topology_printstr[200];
	struct tp_node *node;
	size_t str_len = 0;

	topology_printstr[0] = '\0';
	list_for_each_entry(node, node_list, listm_mapping)
		str_len += sprintf(&topology_printstr[str_len], "0x%04X ", node->gpu_id);

	return topology_printstr;
}

void topology_print(const struct tp_system *sys, const char *message)
{
	struct tp_node *node;
	struct tp_p2pgroup *xgmi_group;

	pr_info("===System Topology=[%12s]==================================\n", message);
	list_for_each_entry(node, &sys->nodes, listm_system) {
		struct tp_iolink *iolink;

		if (!NODE_IS_GPU(node)) {
			pr_info("[%d] CPU\n", node->id);
			pr_info("     cpu_cores_count:%u\n", node->cpu_cores_count);
		} else {
			pr_info("[%d] GPU gpu_id:0x%04X\n", node->id, node->gpu_id);
			pr_info("     vendor_id:%u device_id:%u\n", node->vendor_id, node->device_id);
			pr_info("     vram_public:%c vram_size:%lu\n", node->vram_public ? 'Y' : 'N', node->vram_size);
			pr_info("     io_links_count:%u capability:%u\n", node->io_links_count, node->capability);
			pr_info("     mem_banks_count:%u caches_count:%d lds_size_in_kb:%u\n", node->mem_banks_count,
				node->caches_count, node->lds_size_in_kb);
			pr_info("     simd_count:%u max_waves_per_simd:%u\n", node->simd_count,
				node->max_waves_per_simd);
			pr_info("     num_gws:%u wave_front_size:%u array_count:%u\n", node->num_gws,
				node->wave_front_size, node->array_count);
			pr_info("     simd_arrays_per_engine:%u simd_per_cu:%u\n", node->simd_arrays_per_engine,
				node->simd_per_cu);
			pr_info("     max_slots_scratch_cu:%u cu_per_simd_array:%u\n", node->max_slots_scratch_cu,
				node->cu_per_simd_array);
			pr_info("     num_sdma_engines:%u\n", node->num_sdma_engines);
			pr_info("     num_sdma_xgmi_engines:%u num_sdma_queues_per_engine:%u\n",
				node->num_sdma_xgmi_engines, node->num_sdma_queues_per_engine);
			pr_info("     num_cp_queues:%u fw_version:%u sdma_fw_version:%u\n", node->num_cp_queues,
				node->fw_version, node->sdma_fw_version);
		}
		list_for_each_entry(iolink, &node->iolinks, listm) {
			if (!iolink->valid)
				continue;

			pr_info("     iolink type:%s node-to:%d (0x%04X) node-from:%d bi-dir:%s\n",
				link_type(iolink->type), iolink->node_to_id, iolink->node_to->gpu_id,
				iolink->node_from->id, iolink->peer ? "Y" : "N");
		}
	}

	pr_info("===Groups==========================================================\n");
	list_for_each_entry(xgmi_group, &sys->xgmi_groups, listm_system)
		pr_info("%s\n", p2pgroup_to_str(xgmi_group));
	pr_info("===================================================================\n");
}

void topology_init(struct tp_system *sys)
{
	memset(sys, 0, sizeof(*sys));
	INIT_LIST_HEAD(&sys->nodes);
	INIT_LIST_HEAD(&sys->xgmi_groups);
}

void topology_free(struct tp_system *sys)
{
	while (!list_empty(&sys->nodes)) {
		struct tp_node *node = list_first_entry(&sys->nodes, struct tp_node, listm_system);

		list_del(&node->listm_system);

		while (!list_empty(&node->iolinks)) {
			struct tp_iolink *iolink = list_first_entry(&node->iolinks, struct tp_iolink, listm);

			list_del(&iolink->listm);
			xfree(iolink);
		}
		xfree(node);
	}

	while (!list_empty(&sys->xgmi_groups)) {
		struct tp_p2pgroup *p2pgroup = list_first_entry(&sys->xgmi_groups, struct tp_p2pgroup, listm_system);

		list_del(&p2pgroup->listm_system);
		xfree(p2pgroup);
	}
}

/**
 * @brief Validates iolinks and determine XGMI hives in a system topology
 *
 * On some systems, some GPUs may not be accessible because they are masked by cgroups, but the
 * iolinks to these GPUs are still visible. If the peer GPU is not accessible, we consider that link
 * invalid.
 * In a XGMI hive, each GPU will have a bi-directional iolink to every other GPU. So we create a
 * XGMI group (hive) and add all the GPUs in that hive to the group when iterating over the first
 * GPU in that group.
 *
 * @param sys system topology
 * @return 0 if successful, errno if failed.
 */
int topology_determine_iolinks(struct tp_system *sys)
{
	int ret = 0;
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		struct tp_iolink *iolink;

		list_for_each_entry(iolink, &node->iolinks, listm) {
			struct tp_p2pgroup *group = NULL;
			struct tp_node *peer_node = NULL;
			struct tp_iolink *peer_iolink = NULL;

			peer_node = sys_get_node_by_node_id(sys, iolink->node_to_id);
			if (!peer_node) {
				/* node not accessible, usually because it is masked by cgroups */
				iolink->valid = false;
				continue;
			}
			iolink->valid = true;
			node->num_valid_iolinks++;

			iolink->node_to = peer_node;
			peer_iolink = get_tp_peer_iolink(peer_node, node, iolink->type);
			if (!peer_iolink)
				continue; /* This is a one-dir link */

			/* We confirmed both sides have same type of iolink */
			iolink->peer = peer_iolink;
			peer_iolink->peer = iolink;

			if (iolink->type == TOPO_IOLINK_TYPE_XGMI) {
				group = sys_get_p2pgroup_with_gpu_id(sys, iolink->type, node->gpu_id);
				if (!group) {
					/* This GPU does not already belong to a group so we create
					 * a new group
					 */
					group = sys_add_group(sys, iolink->type);
					if (!group) {
						ret = -ENOMEM;
						goto fail;
					}
					list_add_tail(&node->listm_p2pgroup, &group->nodes);
				}

				/* Also add peer GPU to this group */
				if (!p2pgroup_get_node_by_gpu_id(group, peer_node->gpu_id))
					list_add_tail(&peer_node->listm_p2pgroup, &group->nodes);
			}
		}
	}

fail:
	/* In case of failure, caller function will call topology_free which will free groups that
	 * were successfully allocated
	 */
	return ret;
}

/**
 * @brief Parse system topology
 *
 * Parse system topology exposed by the drivers in /sys/class/kfd/kfd/topology and fill in the
 * system topology structure.
 *
 * @param sys system topology structure to be filled by this function
 * @param message print this message when printing the topology to logs
 * @return 0 if successful, errno if failed.
 */
int topology_parse(struct tp_system *sys, const char *message)
{
	struct dirent *dirent_system;
	DIR *d_system;
	char path[300];
	int ret;

	if (sys->parsed)
		return 0;

	sys->parsed = true;
	INIT_LIST_HEAD(&sys->nodes);
	INIT_LIST_HEAD(&sys->xgmi_groups);

	d_system = opendir(TOPOLOGY_PATH);
	if (!d_system) {
		pr_perror("Can't open %s", TOPOLOGY_PATH);
		return -EACCES;
	}

	while ((dirent_system = readdir(d_system)) != NULL) {
		struct stat stbuf;
		int id, fd;

		/* Only parse numeric directories */
		if (sscanf(dirent_system->d_name, "%d", &id) != 1)
			continue;

		sprintf(path, "%s%s", TOPOLOGY_PATH, dirent_system->d_name);
		if (stat(path, &stbuf)) {
			/* When cgroup is masking some devices, the path exists, but it is not
			 * accessible, this is not an error
			 */
			pr_info("Cannot to access %s\n", path);
			continue;
		}

		if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
			struct tp_node *node;
			int len;
			char gpu_id_path[300];
			char read_buf[7]; /* Max gpu_id len is 6 chars */
			unsigned int gpu_id;

			sprintf(gpu_id_path, "%s/%s/gpu_id", TOPOLOGY_PATH, dirent_system->d_name);
			fd = open(gpu_id_path, O_RDONLY);
			if (fd < 0) {
				pr_perror("Failed to access %s", gpu_id_path);
				continue;
			}

			len = read(fd, read_buf, sizeof(read_buf) - 1);
			close(fd);
			if (len < 0)
				continue;

			read_buf[len] = '\0';

			if (sscanf(read_buf, "%d", &gpu_id) != 1)
				continue;

			node = sys_add_node(sys, id, gpu_id);
			if (!node) {
				ret = -ENOMEM;
				goto fail;
			}

			if (parse_topo_node(node, path)) {
				pr_err("Failed to parse node %s\n", path);
				ret = -EINVAL;
				goto fail;
			}
		}
	}
	closedir(d_system);
	return 0;

fail:
	topology_free(sys);
	return ret;
}

static bool device_properties_match(struct tp_node *src, struct tp_node *dest)
{
	if (src->simd_count == dest->simd_count && src->mem_banks_count == dest->mem_banks_count &&
	    src->io_links_count == dest->io_links_count && src->max_waves_per_simd == dest->max_waves_per_simd &&
	    src->lds_size_in_kb == dest->lds_size_in_kb && src->wave_front_size == dest->wave_front_size &&
	    src->array_count == dest->array_count && src->simd_arrays_per_engine == dest->simd_arrays_per_engine &&
	    src->cu_per_simd_array == dest->cu_per_simd_array && src->simd_per_cu == dest->simd_per_cu &&
	    src->max_slots_scratch_cu == dest->max_slots_scratch_cu && src->vendor_id == dest->vendor_id &&
	    src->device_id == dest->device_id && src->num_sdma_engines == dest->num_sdma_engines &&
	    src->num_sdma_xgmi_engines == dest->num_sdma_xgmi_engines &&
	    src->num_sdma_queues_per_engine == dest->num_sdma_queues_per_engine &&
	    src->num_cp_queues == dest->num_cp_queues && src->vram_public == dest->vram_public &&
	    (!kfd_capability_check || (src->capability == dest->capability)) &&
	    (!kfd_vram_size_check || (src->vram_size <= dest->vram_size)) &&
	    (!kfd_num_gws_check || (src->num_gws <= dest->num_gws)) &&
	    (!kfd_caches_count_check || (src->caches_count <= dest->caches_count)) &&
	    (!kfd_fw_version_check || (src->fw_version <= dest->fw_version)) &&
	    (!kfd_sdma_fw_version_check || (src->sdma_fw_version <= dest->sdma_fw_version))) {
		return true;
	}
	return false;
}

/**
 * @brief Determines whether iolink dest can be used to replace src
 *
 * @param src source iolink
 * @param dest destination iolink
 * @return true if dest can replace src
 */
static bool iolink_match(struct tp_iolink *src, struct tp_iolink *dest)
{
	if (!src->valid)
		return true;

	if (!dest->valid)
		return false;

	if (NODE_IS_GPU(src->node_to) != NODE_IS_GPU(dest->node_to))
		return false;

	/* XGMI link can replace PCIE links */
	if (src->type == TOPO_IOLINK_TYPE_XGMI && dest->type == TOPO_IOLINK_TYPE_PCIE)
		return false;

	/* bi-directional links can replace uni-directional links */
	if (src->peer != NULL && dest->peer == NULL)
		return false;

	return true;
}

/**
 * @brief Determines whether src_node can be mapped to dest_node
 *
 * Nodes compatibility are determined by:
 * 1. Comparing the node properties
 * 2. Making sure iolink mappings to CPUs would be compatible with existing iolink mappings in maps
 *
 * If src_node and dest_node are mappable, then map_device will push the new mapping
 * for src_node -> dest_node into new_maps.
 * @param src_sys system topology information on source system
 * @param dest_sys system topology information on destination system
 * @param src_node source GPU
 * @param dest_node destination GPU
 * @param maps list of existing device maps
 * @param new_maps if nodes are mappable, then GPU and CPU mappings will be added to this list
 * @return true if src_node and dest_node are mappable
 */
static bool map_device(struct tp_system *src_sys, struct tp_system *dest_sys, struct tp_node *src_node,
		       struct tp_node *dest_node, struct device_maps *maps, struct device_maps *new_maps)
{
	struct tp_iolink *src_iolink;

	pr_debug("Evaluating mapping nodes [0x%04X -> 0x%04X]\n", src_node->gpu_id, dest_node->gpu_id);

	/* Compare GPU properties from /sys/class/kfd/kfd/topology/nodes/N/properties */
	if (!device_properties_match(src_node, dest_node)) {
		pr_debug("[0x%04X -> 0x%04X] Device properties do not match\n", src_node->gpu_id, dest_node->gpu_id);
		return false;
	}

	if (src_node->num_valid_iolinks > dest_node->num_valid_iolinks) {
		pr_debug("[0x%04X -> 0x%04X] Mismatch between number of iolinks\n", src_node->gpu_id,
			 dest_node->gpu_id);
		return false;
	}

	list_for_each_entry(src_iolink, &src_node->iolinks, listm) {
		/* Go through list of iolinks to CPU and compare them */

		if (!NODE_IS_GPU(src_iolink->node_to)) {
			bool matched_iolink = false;
			/* This is a iolink to CPU */
			pr_debug("Found link to CPU node:%02d\n", src_iolink->node_to->id);

			if (!kfd_numa_check) {
				struct tp_iolink *dest_iolink;

				list_for_each_entry(dest_iolink, &dest_node->iolinks, listm) {
					if (iolink_match(src_iolink, dest_iolink))
						matched_iolink = true;
				}
			} else {
				uint32_t dest_cpu_node_id;

				dest_cpu_node_id = maps_get_dest_cpu(maps, src_iolink->node_to->id);
				if (dest_cpu_node_id == INVALID_CPU_ID)
					dest_cpu_node_id = maps_get_dest_cpu(new_maps, src_iolink->node_to->id);

				if (dest_cpu_node_id == INVALID_CPU_ID) {
					struct tp_iolink *dest_iolink;
					list_for_each_entry(dest_iolink, &dest_node->iolinks, listm) {
						if (iolink_match(src_iolink, dest_iolink) &&
						    !maps_dest_cpu_mapped(maps, dest_iolink->node_to->id) &&
						    !maps_dest_cpu_mapped(new_maps, dest_iolink->node_to->id)) {
							if (!maps_add_cpu_entry(new_maps, src_iolink->node_to->id,
										dest_iolink->node_to->id))
								/* This is a critical error because
								 * we are out of memory
								 */
								return false;

							matched_iolink = true;
							break;
						}
					}
				} else {
					pr_debug("Existing CPU mapping found [%02d-%02d]\n", src_iolink->node_to->id,
						 dest_cpu_node_id);
					/* Confirm that the link to this CPU is same or better */

					struct tp_iolink *dest_iolink = node_get_iolink_to_node_id(
						dest_node, src_iolink->type, dest_cpu_node_id);

					if (dest_iolink && iolink_match(src_iolink, dest_iolink))
						matched_iolink = true;
				}
			}
			if (!matched_iolink) {
				pr_debug("[0x%04X -> 0x%04X] Mismatch between iolink to CPU\n", src_node->gpu_id,
					 dest_node->gpu_id);

				return false;
			}
		} else {
			/* If GPUs have P2P-PCIe iolinks to this GPU, then at least one CPU will
			 * also have a P2P-PCIe iolink to this GPU, so it seems that we do not need
			 * to consider P2P-PCIe iolinks from GPU to GPU for now. Once P2P-PCIe
			 * iolinks are exposed via p2p_links we may have to add additional code here
			 * to validate P2P-PCIe links between GPUs.
			 */
		}
	}
	pr_debug("[0x%04X -> 0x%04X] Map is possible\n", src_node->gpu_id, dest_node->gpu_id);

	if (!maps_add_gpu_entry(new_maps, src_node->gpu_id, dest_node->gpu_id)) {
		/* This is a critical error because we are out of memory */
		return false;
	}
	maps_print(new_maps);
	return true;
}

/**
 * @brief Determines whether list of GPUs in src_nodes are mappable to dest_nodes
 *
 * This function will pick the first node from src_nodes and iterate through all the nodes in
 * dest_nodes and call map_device to determine whether the node is mappable.
 * If a node from dest_nodes is mappable to the first node from src_nodes:
 * 1. This function will remove the first node from src_nodes and the node from dest_nodes
 * 2. Push sub-mappings (new_maps) generated by map_device into existing mappings (maps)
 * 3. Recursively check whether remaining nodes in src_nodes and dest_nodes are mappable.
 *
 * Once src_nodes is empty then we have successfully mapped all the nodes and maps contains a full
 * list of GPU mappings.
 *
 * If there are no nodes in dest_nodes that can be mapped to the first node in src_nodes, then this
 * means we cannot build a full mapping list with the current list of mappings. We backtrack by
 * popping the newly generated sub-mappings(new_maps) from existing mappings (maps) and add the two
 * nodes back to src_nodes and dest_nodes and return false. When this function returns false, the
 * caller function will try a different path by trying to map the first node from src_nodes to the
 * next node in dest_nodes.
 *
 * @param src_sys system topology information on source system
 * @param dest_sys system topology information on destination system
 * @param src_node list of source GPUs that need to be mapped
 * @param dest_node list of destination GPUs that need to be mapped
 * @param maps list of device maps based on current map path
 * @return true if all nodes from src_nodes and dest_nodes are mappable
 */
static bool map_devices(struct tp_system *src_sys, struct tp_system *dest_sys, struct list_head *src_nodes,
			struct list_head *dest_nodes, struct device_maps *maps)
{
	struct tp_node *src_node, *dest_node, *dest_node_tmp;
	struct device_maps new_maps;

	/* Pick the first src node from the list of nodes and look for a dest node that is mappable.
	 * If we find a mappable destination node, then we add src node and dest node mapping to
	 * device_maps and recursively try to map the remaining nodes in the list.
	 * If there are no more src nodes in the list, then we have found a successful combination
	 * of src to dest nodes that are mappable.
	 */
	if (list_empty(src_nodes)) {
		pr_debug("All nodes mapped successfully\n");
		return true;
	}

	pr_debug("Mapping list src nodes [%s]\n", mapping_list_to_str(src_nodes));
	pr_debug("Mapping list dest nodes [%s]\n", mapping_list_to_str(dest_nodes));

	src_node = list_first_entry(src_nodes, struct tp_node, listm_mapping);
	pr_debug("Looking for match for node 0x%04X\n", src_node->gpu_id);

	list_del(&src_node->listm_mapping);

	list_for_each_entry_safe(dest_node, dest_node_tmp, dest_nodes, listm_mapping) {
		maps_init(&new_maps);
		if (map_device(src_sys, dest_sys, src_node, dest_node, maps, &new_maps)) {
			pr_debug("Matched destination node 0x%04X\n", dest_node->gpu_id);

			/* src node and dest node are mappable, add device_maps generated by
			 * map_device to list of current valid device_maps, and recursively try to
			 * map remaining nodes in the list.
			 */

			list_del(&dest_node->listm_mapping);
			if (maps_push(maps, &new_maps))
				return false;

			if (map_devices(src_sys, dest_sys, src_nodes, dest_nodes, maps)) {
				pr_debug("Matched nodes 0x%04X and after\n", dest_node->gpu_id);
				return true;
			} else {
				/* We could not map remaining nodes in the list. Add dest node back
				 * to list and try to map next dest node in list to current src
				 * node.
				 */
				pr_debug("Nodes after [0x%04X -> 0x%04X] did not match, "
					 "adding list back\n",
					 src_node->gpu_id, dest_node->gpu_id);

				list_add(&dest_node->listm_mapping, dest_nodes);
				maps_pop(maps, &new_maps);
			}
		}
	}
	pr_debug("Failed to map nodes 0x%04X and after\n", src_node->gpu_id);

	/* Either: We could not find a mappable dest node for current node, or we could not build a
	 * combination from the remaining nodes in the lists. Add src node back to the list and
	 * caller function will try next possible combination.
	 */
	list_add(&src_node->listm_mapping, src_nodes);

	return false;
}

/**
 * @brief Determines whether list of GPUs in src_xgmi_groups are mappable to list of GPUs in
 * dest_xgmi_groups
 *
 * This function will pick the first XGMI group (hive) from src_xgmi_groups and iterate through the
 * XGMI groups in dest_xgmi_groups. If the group in dest_xgmi_groups is mappable then this function
 * will remove the hives from src_xgmi_groups and dest_xgmi_groups and recursively try to map the
 * remaining hives in src_xgmi_groups and dest_xgmi_groups.
 *
 * If src_xgmi_groups is empty, then this means that we have successfully mapped all the XGMI hives
 * and we have a full list of GPU mappings in maps.
 *
 * If we cannot find a hive inside dest_xgmi_groups that is mappable to the first hive from
 * src_xgmi_groups, then this means that this path is not valid and we need to backtrack. We
 * backtrack by adding the hives back into src_xgmi_groups and dest_xgmi_groups and returning false.
 * The caller function will then try a different path by trying to map the first hive in
 * src_xgmi_groups to the next hive in dest_xgmi_groups.
 *
 * @param src_sys system topology information on source system
 * @param dest_sys system topology information on destination system
 * @param src_xgmi_groups list of source XGMI hives that need to be mapped
 * @param dest_xgmi_groups list of destination XGMI hives that need to be mapped
 * @param maps list of device maps based on current map path
 * @return true if all nodes from src_nodes and dest_nodes are mappable
 */
bool match_xgmi_groups(struct tp_system *src_sys, struct tp_system *dest_sys, struct list_head *src_xgmi_groups,
		       struct list_head *dest_xgmi_groups, struct device_maps *maps)
{
	struct tp_p2pgroup *src_group;
	struct tp_p2pgroup *dest_group;
	struct tp_p2pgroup *dest_group_tmp;

	if (list_empty(src_xgmi_groups)) {
		pr_debug("All groups matched successfully\n");
		return true;
	}

	/* Pick the first src XGMI group from the list. Then try to match src XGMI group with a
	 * dest XGMI group. If we have a dest XGMI group that is mappable, then we try to
	 * recursively map the next src XGMI group in the list, with remaining dest XGMI groups.
	 * If there are no more src XGMI groups in the list, then this means we have successfully
	 * mapped all the groups and we have a valid device_maps
	 */
	src_group = list_first_entry(src_xgmi_groups, struct tp_p2pgroup, listm_system);
	pr_debug("Looking for match for group [%s]\n", p2pgroup_to_str(src_group));

	list_del(&src_group->listm_system);

	list_for_each_entry_safe(dest_group, dest_group_tmp, dest_xgmi_groups, listm_system) {
		struct tp_node *node;

		LIST_HEAD(src_nodes);
		LIST_HEAD(dest_nodes);

		if (src_group->num_nodes > dest_group->num_nodes)
			continue;

		pr_debug("Trying destination group [%s]\n", p2pgroup_to_str(dest_group));

		list_for_each_entry(node, &src_group->nodes, listm_p2pgroup)
			list_add_tail(&node->listm_mapping, &src_nodes);

		list_for_each_entry(node, &dest_group->nodes, listm_p2pgroup)
			list_add_tail(&node->listm_mapping, &dest_nodes);

		/* map_devices will populate maps if successful */
		if (map_devices(src_sys, dest_sys, &src_nodes, &dest_nodes, maps)) {
			/* All the nodes in current src XGMI group are mappable with nodes in
			 * current dest XGMI group. Remove the current groups from the lists
			 * and recursively try to match remaining groups
			 */
			list_del(&dest_group->listm_system);
			pr_debug("Matched destination group [%s]\n", p2pgroup_to_str(dest_group));
			if (match_xgmi_groups(src_sys, dest_sys, src_xgmi_groups, dest_xgmi_groups, maps)) {
				pr_debug("Matched subgroups of [%s]\n", p2pgroup_to_str(dest_group));

				xfree(src_group);
				xfree(dest_group);
				return true;
			} else {
				/* We were not able to map the remaining XGMI groups so we add the
				 * current dest XGMI group back to the list of unmapped groups, and
				 * try to map current src XGMI group with the next dest XGMI in the
				 * list of XGMI groups
				 */
				list_add(&dest_group->listm_system, dest_xgmi_groups);
			}
		}
	}

	/* We have not found a mappable dest XGMI group. We discard this combination. If this is
	 * the first src XGMI group in the list, then it is not possible to match the XGMI groups.
	 * If this was a recursive call, then the calling instance of function will try the next
	 * combination of XGMI groups
	 */

	pr_debug("Failed to match groups [%s]\n", p2pgroup_to_str(src_group));
	list_add_tail(&src_group->listm_system, src_xgmi_groups);

	return false;
}

/**
 * @brief Builds a list of GPU mappings from source topology to destination topology
 *
 * The topology on the destination system may not be identical to the topology on the source
 * system, e.g There can be GPUs with different device ID's and they may be enumerated in a
 * different order. This function builds a list of GPU mappings from the source topology to the
 * destination topology and stores it in maps.
 *
 * The function will first validate all the iolinks and determine XGMI groups (hives) by calling the
 * topology_determine_iolinks(). It will then try to match the GPUs that belong to XGMI hives and
 * after that, match the remaining GPUs.
 *
 * @param src_sys system topology information on source system
 * @param dest_sys system topology information on destination system
 * @param maps list of device maps that was generated by this function
 * @return true if we were able to build a full list of GPU mappings.
 */
int set_restore_gpu_maps(struct tp_system *src_sys, struct tp_system *dest_sys, struct device_maps *maps)
{
	struct tp_node *node;
	int ret = 0;
	int src_num_gpus = 0;
	int dest_num_gpus = 0;

	maps_init(maps);

	ret = topology_determine_iolinks(src_sys);
	if (ret) {
		pr_err("Failed to determine iolinks from source (checkpointed) topology\n");
		return ret;
	}
	topology_print(src_sys, "Source    ");

	ret = topology_determine_iolinks(dest_sys);
	if (ret) {
		pr_err("Failed to determine iolinks from destination (local) topology\n");
		return ret;
	}
	topology_print(dest_sys, "Destination");

	/* Make sure we have same number of GPUs in src and dest */
	list_for_each_entry(node, &src_sys->nodes, listm_system) {
		if (NODE_IS_GPU(node))
			src_num_gpus++;
	}
	list_for_each_entry(node, &dest_sys->nodes, listm_system) {
		if (NODE_IS_GPU(node))
			dest_num_gpus++;
	}

	if (src_num_gpus != dest_num_gpus) {
		pr_err("Number of devices mismatch (checkpointed:%d local:%d)\n", src_num_gpus, dest_num_gpus);
		return -EINVAL;
	}

	if (src_sys->num_xgmi_groups > dest_sys->num_xgmi_groups) {
		pr_err("Number of xgmi groups mismatch (checkpointed:%d local:%d)\n", src_sys->num_xgmi_groups,
		       dest_sys->num_xgmi_groups);
		return -EINVAL;
	}

	/* First try to match the XGMI hives */
	if (src_sys->num_xgmi_groups) {
		if (!match_xgmi_groups(src_sys, dest_sys, &src_sys->xgmi_groups, &dest_sys->xgmi_groups, maps)) {
			pr_err("Failed to match all GPU groups\n");
			return -EINVAL;
		}
		pr_info("Current maps after XGMI groups matched\n");
		maps_print(maps);
	}

	/* We matched all the XGMI hives, now match remaining GPUs */
	LIST_HEAD(src_nodes);
	LIST_HEAD(dest_nodes);

	list_for_each_entry(node, &src_sys->nodes, listm_system) {
		if (NODE_IS_GPU(node) && !maps_get_dest_gpu(maps, node->gpu_id))
			list_add(&node->listm_mapping, &src_nodes);
	}

	list_for_each_entry(node, &dest_sys->nodes, listm_system) {
		if (NODE_IS_GPU(node) && !maps_dest_gpu_mapped(maps, node->gpu_id))
			list_add(&node->listm_mapping, &dest_nodes);
	}

	if (!map_devices(src_sys, dest_sys, &src_nodes, &dest_nodes, maps)) {
		pr_err("Failed to match remaining nodes\n");
		return -EINVAL;
	}

	pr_info("Maps after all nodes matched\n");
	maps_print(maps);

	return ret;
}
