
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

#include <dirent.h>
#include "common/list.h"

#include "xmalloc.h"
#include "kfd_ioctl.h"
#include "amdgpu_plugin_topology.h"

#define TOPOLOGY_PATH   "/sys/class/kfd/kfd/topology/nodes/"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef DEBUG
#define plugin_log_msg(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
#define plugin_log_msg(fmt, ...) {}
#endif

static const char *link_type(uint32_t type){
	switch(type) {
		case TOPO_IOLINK_TYPE_PCIE:
			return "PCIe";
		case TOPO_IOLINK_TYPE_XGMI:
			return "XGMI";
	}
	return "Unsupported";
}

static struct tp_node *p2pgroup_get_node_by_gpu_id(const struct tp_p2pgroup *group,
					       const uint32_t gpu_id)
{
	struct tp_node *node;

	list_for_each_entry(node, &group->nodes, listm_p2pgroup) {
		if (node->gpu_id == gpu_id)
			return node;
	}
	return NULL;
}

struct tp_node *sys_get_node_by_render_minor(const struct tp_system *sys,
						const int drm_render_minor)
{
	struct tp_node *node;

	list_for_each_entry(node, &sys->nodes, listm_system) {
		if (node->drm_render_minor == drm_render_minor)
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

static struct tp_iolink *get_tp_peer_iolink(const struct tp_node *from_node,
				     const struct tp_node *to_node,
				     const uint8_t type)
{
	struct tp_iolink *iolink;

	list_for_each_entry(iolink, &from_node->iolinks, listm) {
		if (iolink->node_to_id == to_node->id && iolink->type == type)
			return iolink;
	}
	return NULL;
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
		pr_perror("Failed to access %s\n", path);
		return -EFAULT;
	}

	while (fgets(line, sizeof(line), file)) {
		char name[30];
		uint64_t value;

		memset(name, 0, sizeof(name));
		if (!get_prop(line, name, &value))
			goto fail;

		if (!strcmp(name, "cpu_cores_count")) dev->cpu_cores_count = (uint32_t) value;
		else if (!strcmp(name, "simd_count")) dev->simd_count = (uint32_t) value;
		else if (!strcmp(name, "mem_banks_count")) dev->mem_banks_count = (uint32_t) value;
		else if (!strcmp(name, "caches_count")) dev->caches_count = (uint32_t) value;
		else if (!strcmp(name, "io_links_count")) dev->io_links_count = (uint32_t) value;
		else if (!strcmp(name, "max_waves_per_simd")) dev->max_waves_per_simd = (uint32_t) value;
		else if (!strcmp(name, "lds_size_in_kb")) dev->lds_size_in_kb = (uint32_t) value;
		else if (!strcmp(name, "num_gws")) dev->num_gws = (uint32_t) value;
		else if (!strcmp(name, "wave_front_size")) dev->wave_front_size = (uint32_t) value;
		else if (!strcmp(name, "array_count")) dev->array_count = (uint32_t) value;
		else if (!strcmp(name, "simd_arrays_per_engine")) dev->simd_arrays_per_engine = (uint32_t) value;
		else if (!strcmp(name, "cu_per_simd_array")) dev->cu_per_simd_array = (uint32_t) value;
		else if (!strcmp(name, "simd_per_cu")) dev->simd_per_cu = (uint32_t) value;
		else if (!strcmp(name, "max_slots_scratch_cu")) dev->max_slots_scratch_cu = (uint32_t) value;
		else if (!strcmp(name, "vendor_id")) dev->vendor_id = (uint32_t) value;
		else if (!strcmp(name, "device_id")) dev->device_id = (uint32_t) value;
		else if (!strcmp(name, "domain")) dev->domain = (uint32_t) value;
		else if (!strcmp(name, "drm_render_minor")) dev->drm_render_minor = (uint32_t) value;
		else if (!strcmp(name, "hive_id")) dev->hive_id = value;
		else if (!strcmp(name, "num_sdma_engines")) dev->num_sdma_engines = (uint32_t) value;
		else if (!strcmp(name, "num_sdma_xgmi_engines")) dev->num_sdma_xgmi_engines = (uint32_t) value;
		else if (!strcmp(name, "num_sdma_queues_per_engine")) dev->num_sdma_queues_per_engine = (uint32_t) value;
		else if (!strcmp(name, "num_cp_queues")) dev->num_cp_queues = (uint32_t) value;
		else if (!strcmp(name, "fw_version")) dev->fw_version = (uint32_t) value;
		else if (!strcmp(name, "capability")) dev->capability = (uint32_t) value;
		else if (!strcmp(name, "sdma_fw_version")) dev->sdma_fw_version = (uint32_t) value;

		if (!dev->gpu_id && dev->cpu_cores_count >= 1) {
			/* This is a CPU - we do not need to parse the other information */
			break;
		}
	}

	fclose(file);
	return 0;
fail:
	pr_err("Failed to parse line = %s \n", line);
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
		pr_perror("Can't open %s\n", path);
		return -EACCES;
	}

	while ((dirent_node = readdir(d_node)) != NULL) {
		char line[300];
		char bank_path[300];
		struct stat st;
		int id;

		heap_type = 0;
		mem_size = 0;

		/* Only parse numeric directories */
		if (sscanf(dirent_node->d_name, "%d", &id) != 1)
			continue;

		sprintf(bank_path, "%s/%s", path, dirent_node->d_name);
		if (stat(bank_path, &st)) {
			pr_err("Cannot to access %s\n", path);
			ret = -EACCES;
			goto fail;
		}
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			char properties_path[300];

			sprintf(properties_path, "%s/properties", bank_path);

			file = fopen(properties_path, "r");
			if (!file) {
				pr_perror("Failed to access %s\n", properties_path);
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

				if (!strcmp(name, "heap_type")) heap_type = (uint32_t) value;
				if (!strcmp(name, "size_in_bytes")) mem_size = value;
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

	sprintf(path, "%s/io_links", dir_path);

	d_node = opendir(path);
	if (!d_node) {
		pr_perror("Can't open %s\n", path);
		return -EACCES;
	}

	while ((dirent_node = readdir(d_node)) != NULL) {
		char line[300];
		char iolink_path[300];
		struct stat st;
		int id;

		uint32_t iolink_type = 0;
		uint32_t node_to_id = 0;

		/* Only parse numeric directories */
		if (sscanf(dirent_node->d_name, "%d", &id) != 1)
			continue;

		sprintf(iolink_path, "%s/%s", path, dirent_node->d_name);
		if (stat(iolink_path, &st)) {
			pr_err("Cannot to access %s\n", path);
			ret = -EACCES;
			goto fail;
		}
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			char properties_path[300];

			sprintf(properties_path, "%s/properties", iolink_path);

			file = fopen(properties_path, "r");
			if (!file) {
				pr_perror("Failed to access %s\n", properties_path);
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

				if (!strcmp(name, "type")) iolink_type = (uint32_t) value;
				if (!strcmp(name, "node_to")) node_to_id = (uint32_t) value;
			}
			fclose(file);
			file = NULL;
		}

		/* We only store the link information for now, then once all topology parsing is
		 * finished we will confirm iolinks */
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
static int parse_topo_node(struct tp_node *node, const char* dir_path)
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

static const char* p2pgroup_to_str(struct tp_p2pgroup *group)
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
			pr_info("     vendor_id:%u device_id:%u\n",
					node->vendor_id, node->device_id);
			pr_info("     vram_public:%c vram_size:%lu\n",
					node->vram_public ? 'Y' : 'N', node->vram_size);
			pr_info("     io_links_count:%u capability:%u \n",
					node->io_links_count, node->capability);
			pr_info("     mem_banks_count:%u caches_count:%d lds_size_in_kb:%u\n",
					node->mem_banks_count, node->caches_count, node->lds_size_in_kb);
			pr_info("     simd_count:%u max_waves_per_simd:%u \n",
					node->simd_count, node->max_waves_per_simd);
			pr_info("     num_gws:%u wave_front_size:%u array_count:%u\n",
					node->num_gws, node->wave_front_size, node->array_count);
			pr_info("     simd_arrays_per_engine:%u simd_per_cu:%u\n",
					node->simd_arrays_per_engine, node->simd_per_cu);
			pr_info("     max_slots_scratch_cu:%u cu_per_simd_array:%u\n",
					node->max_slots_scratch_cu, node->cu_per_simd_array);
			pr_info("     num_sdma_engines:%u\n",
					node->num_sdma_engines);
			pr_info("     num_sdma_xgmi_engines:%u num_sdma_queues_per_engine:%u\n",
					node->num_sdma_xgmi_engines, node->num_sdma_queues_per_engine);
			pr_info("     num_cp_queues:%u fw_version:%u sdma_fw_version:%u\n",
					node->num_cp_queues, node->fw_version, node->sdma_fw_version);
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
		struct tp_node* node = list_first_entry(&sys->nodes, struct tp_node, listm_system);
		list_del(&node->listm_system);

		while (!list_empty(&node->iolinks)) {
			struct tp_iolink *iolink = list_first_entry(&node->iolinks, struct tp_iolink, listm);
			list_del(&iolink->listm);
			xfree(iolink);
		}
		xfree(node);
	}

	while (!list_empty(&sys->xgmi_groups)) {
		struct tp_p2pgroup* p2pgroup = list_first_entry(&sys->xgmi_groups, struct tp_p2pgroup, listm_system);
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
					   a new group */
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
	 * were successfully allocated */
	return ret;
}

/**
 * @brief Parse system topology
 *
 * Parse system topology exposed by the drivers in /sys/class/kfd/kfd/topology and fill in the
 * system topology structure.
 *
 * @param sys system topology structure to be filled by this function
 * @param message message to print when printing the topology to logs
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
		pr_perror("Can't open %s\n", TOPOLOGY_PATH);
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
			 * accessible, this is not an error */
			pr_info("Cannot to access %s\n", path);
			continue;
		}

		if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
			struct tp_node *node;
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
				pr_err("Failed to parse node %s", path);
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
