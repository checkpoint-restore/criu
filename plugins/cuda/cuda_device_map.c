#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cuda_device_map.h"
#include "cuda.pb-c.h"
#include "criu-plugin.h"
#include "criu-log.h"
#include "cr_options.h"
#include "img-streamer.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CUDA_GPU_INVENTORY_IMAGE "cuda-gpu-inventory.img"
#define CUDA_GPU_UUID_SIZE 16

typedef int CUresult;
typedef struct {
	unsigned char bytes[CUDA_GPU_UUID_SIZE];
} CUuuid;

typedef CUresult (*cuda_init_fn)(unsigned int flags);
typedef CUresult (*cuda_device_get_count_fn)(int *count);
typedef CUresult (*cuda_device_get_uuid_fn)(CUuuid *uuid, int device);

struct cuda_device_api {
	void *handle;
	cuda_init_fn init;
	cuda_device_get_count_fn get_count;
	cuda_device_get_uuid_fn get_uuid;
};

struct cuda_saved_environment {
	char *visible_devices;
	char *device_order;
	bool visible_devices_set;
	bool device_order_set;
	bool changed;
};

static int cuda_img_read(int fd, void *buf, size_t len)
{
	char *ptr = buf;

	while (len) {
		ssize_t ret = read(fd, ptr, len);

		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (ret == 0)
			return -EIO;

		ptr += ret;
		len -= ret;
	}

	return 0;
}

static int cuda_img_write(int fd, const void *buf, size_t len)
{
	const char *ptr = buf;

	while (len) {
		ssize_t ret = write(fd, ptr, len);

		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (ret == 0)
			return -EIO;

		ptr += ret;
		len -= ret;
	}

	return 0;
}

static int cuda_open_inventory_image(bool write_image, size_t *size)
{
	int fd;
	int flags;
	int ret;

	if (opts.stream) {
		fd = img_streamer_open(CUDA_GPU_INVENTORY_IMAGE,
				       write_image ? O_DUMP : O_RSTR);
		if (fd < 0)
			return fd == -1 ? -EIO : fd;
	} else {
		flags = write_image ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY;
		fd = openat(criu_get_image_dir(), CUDA_GPU_INVENTORY_IMAGE, flags, 0600);
		if (fd < 0)
			return -errno;
	}

	if (write_image)
		ret = cuda_img_write(fd, size, sizeof(*size));
	else
		ret = cuda_img_read(fd, size, sizeof(*size));
	if (ret) {
		close(fd);
		return ret;
	}

	return fd;
}

static void *cuda_get_symbol(void *handle, const char *name)
{
	const char *error;
	void *symbol;

	dlerror();
	symbol = dlsym(handle, name);
	error = dlerror();
	if (error) {
		pr_err("Unable to resolve %s from libcuda.so.1: %s\n", name, error);
		return NULL;
	}

	return symbol;
}

static void cuda_device_api_fini(struct cuda_device_api *api)
{
	if (api->handle)
		dlclose(api->handle);

	memset(api, 0, sizeof(*api));
}

static int cuda_device_api_init(struct cuda_device_api *api)
{
	api->handle = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);
	if (!api->handle) {
		pr_err("Cannot load libcuda.so.1: %s\n", dlerror());
		return -1;
	}

	api->init = (cuda_init_fn)cuda_get_symbol(api->handle, "cuInit");
	api->get_count = (cuda_device_get_count_fn)cuda_get_symbol(api->handle, "cuDeviceGetCount");
	api->get_uuid = (cuda_device_get_uuid_fn)cuda_get_symbol(api->handle, "cuDeviceGetUuid");
	if (!api->init || !api->get_count || !api->get_uuid) {
		cuda_device_api_fini(api);
		return -1;
	}

	return 0;
}

static char *cuda_copy_environment(const char *name, bool *is_set)
{
	const char *value = getenv(name);
	char *copy;

	*is_set = value != NULL;
	if (!value)
		return NULL;

	copy = strdup(value);
	if (!copy)
		pr_err("Unable to save %s before CUDA device enumeration\n", name);

	return copy;
}

static int cuda_prepare_environment(struct cuda_saved_environment *saved)
{
	saved->visible_devices = cuda_copy_environment("CUDA_VISIBLE_DEVICES",
					       &saved->visible_devices_set);
	if (saved->visible_devices_set && !saved->visible_devices) {
		saved->visible_devices_set = false;
		return -ENOMEM;
	}

	saved->device_order = cuda_copy_environment("CUDA_DEVICE_ORDER",
					    &saved->device_order_set);
	if (saved->device_order_set && !saved->device_order) {
		free(saved->visible_devices);
		saved->visible_devices = NULL;
		saved->device_order_set = false;
		return -ENOMEM;
	}

	saved->changed = true;
	if (unsetenv("CUDA_VISIBLE_DEVICES") || unsetenv("CUDA_DEVICE_ORDER")) {
		pr_err("Unable to prepare the environment for CUDA device enumeration\n");
		return -errno;
	}

	return 0;
}

static void cuda_restore_environment(struct cuda_saved_environment *saved)
{
	if (!saved->changed) {
		free(saved->visible_devices);
		free(saved->device_order);
		return;
	}

	if (saved->visible_devices_set) {
		if (setenv("CUDA_VISIBLE_DEVICES", saved->visible_devices, 1))
			pr_err("Unable to restore CUDA_VISIBLE_DEVICES: %s\n", strerror(errno));
	} else if (unsetenv("CUDA_VISIBLE_DEVICES")) {
		pr_err("Unable to restore CUDA_VISIBLE_DEVICES: %s\n", strerror(errno));
	}

	if (saved->device_order_set) {
		if (setenv("CUDA_DEVICE_ORDER", saved->device_order, 1))
			pr_err("Unable to restore CUDA_DEVICE_ORDER: %s\n", strerror(errno));
	} else if (unsetenv("CUDA_DEVICE_ORDER")) {
		pr_err("Unable to restore CUDA_DEVICE_ORDER: %s\n", strerror(errno));
	}

	free(saved->visible_devices);
	free(saved->device_order);
	memset(saved, 0, sizeof(*saved));
}

static int cuda_write_inventory(const CudaGpuInventory *inventory)
{
	uint8_t *data = NULL;
	size_t size;
	int fd;
	int ret;

	size = cuda_gpu_inventory__get_packed_size(inventory);
	data = malloc(size);
	if (!data)
		return -ENOMEM;

	if (cuda_gpu_inventory__pack(inventory, data) != size) {
		pr_err("Failed to pack CUDA GPU inventory\n");
		free(data);
		return -EINVAL;
	}

	fd = cuda_open_inventory_image(true, &size);
	if (fd < 0) {
		free(data);
		return fd;
	}

	ret = cuda_img_write(fd, data, size);
	if (close(fd) && !ret)
		ret = -errno;
	free(data);
	return ret;
}

int cuda_gpu_inventory_dump(void)
{
	struct cuda_saved_environment saved = {};
	struct cuda_device_api api = {};
	CudaGpuInventory inventory = CUDA_GPU_INVENTORY__INIT;
	CudaGpu *gpu_values = NULL;
	CudaGpu **gpus = NULL;
	unsigned char (*uuids)[CUDA_GPU_UUID_SIZE] = NULL;
	int device_count;
	int ret = -1;

	if (cuda_prepare_environment(&saved))
		goto out;

	if (cuda_device_api_init(&api))
		goto out;

	if (api.init(0) != 0) {
		pr_err("cuInit failed while collecting CUDA GPU inventory\n");
		goto out;
	}
	if (api.get_count(&device_count) != 0 || device_count < 0) {
		pr_err("cuDeviceGetCount failed while collecting CUDA GPU inventory\n");
		goto out;
	}

	if (device_count > 0) {
		gpu_values = calloc((size_t)device_count, sizeof(*gpu_values));
		gpus = calloc((size_t)device_count, sizeof(*gpus));
		uuids = calloc((size_t)device_count, sizeof(*uuids));
		if (!gpu_values || !gpus || !uuids) {
			ret = -ENOMEM;
			goto out;
		}
	}

	for (int i = 0; i < device_count; i++) {
		if (api.get_uuid((CUuuid *)uuids[i], i) != 0) {
			pr_err("cuDeviceGetUuid failed for CUDA device %d\n", i);
			goto out;
		}

		cuda_gpu__init(&gpu_values[i]);
		gpu_values[i].has_ordinal = 1;
		gpu_values[i].ordinal = i;
		gpu_values[i].has_uuid = 1;
		gpu_values[i].uuid.len = CUDA_GPU_UUID_SIZE;
		gpu_values[i].uuid.data = uuids[i];
		gpus[i] = &gpu_values[i];
	}

	inventory.has_version = 1;
	inventory.version = 1;
	inventory.n_gpus = (size_t)device_count;
	inventory.gpus = gpus;
	ret = cuda_write_inventory(&inventory);
	if (!ret)
		pr_info("Saved UUIDs for %d CUDA GPUs\n", device_count);

out:
	cuda_device_api_fini(&api);
	cuda_restore_environment(&saved);
	free(gpu_values);
	free(gpus);
	free(uuids);
	return ret;
}
