#ifndef CUDA_DEVICE_MAP_H
#define CUDA_DEVICE_MAP_H

#include "cuda_checkpoint.h"

struct cuda_device_map {
	CUcheckpointGpuPair *pairs;
	unsigned int count;
	char *cli_value;
};

int cuda_device_map_validate(const char *value);
int cuda_device_map_resolve(const char *value, struct cuda_device_map *map);
void cuda_device_map_fini(struct cuda_device_map *map);

int cuda_gpu_inventory_dump(void);
int cuda_gpu_inventory_restore_init(void);
void cuda_gpu_inventory_fini(void);

#endif /* CUDA_DEVICE_MAP_H */
