#ifndef __KFD_PLUGIN_TOPOLOGY_H__
#define __KFD_PLUGIN_TOPOLOGY_H__

#define DRM_FIRST_RENDER_NODE 128
#define DRM_LAST_RENDER_NODE  255

#define TOPO_HEAP_TYPE_PUBLIC  1 /* HSA_HEAPTYPE_FRAME_BUFFER_PUBLIC */
#define TOPO_HEAP_TYPE_PRIVATE 2 /* HSA_HEAPTYPE_FRAME_BUFFER_PRIVATE */

#define TOPO_IOLINK_TYPE_ANY  0	 /* HSA_IOLINKTYPE_UNDEFINED */
#define TOPO_IOLINK_TYPE_PCIE 2	 /* HSA_IOLINKTYPE_PCIEXPRESS */
#define TOPO_IOLINK_TYPE_XGMI 11 /* HSA_IOLINK_TYPE_XGMI */

#define NODE_IS_GPU(node) ((node)->gpu_id != 0)
#define INVALID_CPU_ID	  0xFFFF

/*************************************** Structures ***********************************************/
struct tp_node;

struct tp_iolink {
	struct list_head listm;
	uint32_t type;
	uint32_t node_to_id;
	struct tp_node *node_to;
	struct tp_node *node_from;
	bool valid;		/* Set to false if target node is not accessible */
	struct tp_iolink *peer; /* If link is bi-directional, peer link */
};

struct tp_node {
	uint32_t id;
	uint32_t gpu_id;
	uint32_t cpu_cores_count;
	uint32_t simd_count;
	uint32_t mem_banks_count;
	uint32_t caches_count;
	uint32_t io_links_count;
	uint32_t max_waves_per_simd;
	uint32_t lds_size_in_kb;
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
	uint32_t fw_version;
	uint32_t capability;
	uint32_t sdma_fw_version;
	bool vram_public;
	uint64_t vram_size;

	struct list_head listm_system;
	struct list_head listm_p2pgroup;
	struct list_head listm_mapping; /* Used only during device mapping */

	uint32_t num_valid_iolinks;
	struct list_head iolinks;

	int drm_fd;
};

struct tp_p2pgroup {
	uint32_t type;
	uint32_t num_nodes;
	struct list_head listm_system;
	struct list_head nodes;
};

struct tp_system {
	bool parsed;
	uint32_t num_nodes;
	struct list_head nodes;
	uint32_t num_xgmi_groups;
	struct list_head xgmi_groups;
};

struct id_map {
	uint32_t src;
	uint32_t dest;

	struct list_head listm;
};

struct device_maps {
	struct list_head cpu_maps; /* CPUs are mapped using node_id */
	struct list_head gpu_maps;

	struct list_head *tail_cpu; /* GPUs are mapped using gpu_id */
	struct list_head *tail_gpu;
};

/**************************************** Functions ***********************************************/
void topology_init(struct tp_system *sys);
void topology_free(struct tp_system *topology);

int topology_parse(struct tp_system *topology, const char *msg);
int topology_determine_iolinks(struct tp_system *sys);
void topology_print(const struct tp_system *sys, const char *msg);

int topology_gpu_count(struct tp_system *topology);

struct id_map *maps_add_gpu_entry(struct device_maps *maps, const uint32_t src_id, const uint32_t dest_id);

struct tp_node *sys_add_node(struct tp_system *sys, uint32_t id, uint32_t gpu_id);
struct tp_iolink *node_add_iolink(struct tp_node *node, uint32_t type, uint32_t node_to_id);

struct tp_node *sys_get_node_by_gpu_id(const struct tp_system *sys, const uint32_t gpu_id);
struct tp_node *sys_get_node_by_render_minor(const struct tp_system *sys, const int drm_render_minor);
struct tp_node *sys_get_node_by_index(const struct tp_system *sys, uint32_t index);

int node_get_drm_render_device(struct tp_node *node);
void sys_close_drm_render_devices(struct tp_system *sys);

int set_restore_gpu_maps(struct tp_system *tp_checkpoint, struct tp_system *tp_local, struct device_maps *maps);

uint32_t maps_get_dest_gpu(const struct device_maps *maps, const uint32_t src_id);

void maps_init(struct device_maps *maps);
void maps_free(struct device_maps *maps);

#endif /* __KFD_PLUGIN_TOPOLOGY_H__ */
