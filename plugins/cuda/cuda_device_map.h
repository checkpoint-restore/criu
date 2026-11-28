#ifndef CUDA_DEVICE_MAP_H
#define CUDA_DEVICE_MAP_H

#include "cuda_checkpoint.h"

#include <stdbool.h>
#include <stddef.h>

#define CUDA_GPU_INVENTORY_MAX_GPUS 65536

struct cuda_device_map {
	CUcheckpointGpuPair *pairs;
	unsigned int count;
	char *cli_value;
};

int cuda_device_map_validate(const char *value);
int cuda_device_map_resolve(const char *value, struct cuda_device_map *map);
void cuda_device_map_fini(struct cuda_device_map *map);

/*
 * Plugin-private images: a uint32 byte count, then the payload. A missing
 * image opened for reading returns -ENOENT without logging.
 */
int cuda_open_image(const char *name, bool write_image, size_t *size);
int cuda_remove_image(const char *name);
int cuda_img_read(int fd, void *buf, size_t len);
int cuda_img_write(int fd, const void *buf, size_t len);
int cuda_img_at_eof(int fd);

int cuda_gpu_inventory_dump(void);
int cuda_gpu_inventory_restore_init(void);
void cuda_gpu_inventory_fini(void);

#endif /* CUDA_DEVICE_MAP_H */
