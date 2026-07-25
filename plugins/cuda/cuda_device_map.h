#ifndef CUDA_DEVICE_MAP_H
#define CUDA_DEVICE_MAP_H

#include "cuda_checkpoint.h"

int cuda_gpu_inventory_dump(void);
int cuda_gpu_inventory_restore_init(void);
void cuda_gpu_inventory_fini(void);
int cuda_get_device_map(CUcheckpointGpuPair **pairs, unsigned int *count);
void cuda_free_device_map(CUcheckpointGpuPair *pairs);

#endif /* CUDA_DEVICE_MAP_H */
