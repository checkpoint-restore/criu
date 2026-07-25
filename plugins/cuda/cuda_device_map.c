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
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CUDA_GPU_INVENTORY_IMAGE "cuda-gpu-inventory.img"
#define CUDA_GPU_UUID_SIZE 16
#define CUDA_GPU_INVENTORY_VERSION 1
#define CUDA_GPU_INVENTORY_MAX_SIZE (16 * 1024 * 1024)
#define CUDA_GPU_INVENTORY_MAX_GPUS 65536

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
	uint32_t image_size;
	int fd;
	int flags;
	int ret;

	if (write_image) {
		if (*size > UINT32_MAX)
			return -E2BIG;
		image_size = (uint32_t)*size;
	}

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
		ret = cuda_img_write(fd, &image_size, sizeof(image_size));
	else
		ret = cuda_img_read(fd, &image_size, sizeof(image_size));
	if (ret) {
		close(fd);
		return ret;
	}
	if (!write_image)
		*size = image_size;

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

struct cuda_gpu_list {
	CudaGpuInventory inventory;
	CudaGpu *gpu_values;
	CudaGpu **gpus;
	unsigned char (*uuids)[CUDA_GPU_UUID_SIZE];
};

static CudaGpuInventory *cuda_saved_inventory;

void cuda_gpu_inventory_fini(void)
{
	if (cuda_saved_inventory)
		cuda_gpu_inventory__free_unpacked(cuda_saved_inventory, NULL);
	cuda_saved_inventory = NULL;
}

static void cuda_gpu_list_fini(struct cuda_gpu_list *list)
{
	free(list->gpu_values);
	free(list->gpus);
	free(list->uuids);
	memset(list, 0, sizeof(*list));
}

static int cuda_enumerate_gpus(struct cuda_gpu_list *list)
{
	struct cuda_saved_environment saved = {};
	struct cuda_device_api api = {};
	int device_count;
	int ret;

	memset(list, 0, sizeof(*list));
	cuda_gpu_inventory__init(&list->inventory);

	ret = cuda_prepare_environment(&saved);
	if (ret)
		goto out;

	ret = cuda_device_api_init(&api);
	if (ret)
		goto out;

	if (api.init(0) != CUDA_SUCCESS) {
		pr_err("cuInit failed while collecting CUDA GPU inventory\n");
		ret = -1;
		goto out;
	}
	if (api.get_count(&device_count) != CUDA_SUCCESS || device_count <= 0) {
		pr_err("cuDeviceGetCount failed while collecting CUDA GPU inventory\n");
		ret = -1;
		goto out;
	}
	if ((unsigned int)device_count > CUDA_GPU_INVENTORY_MAX_GPUS) {
		pr_err("Too many CUDA GPUs to save in the inventory: %d\n", device_count);
		ret = -E2BIG;
		goto out;
	}

	if (device_count > 0) {
		list->gpu_values = calloc((size_t)device_count, sizeof(*list->gpu_values));
		list->gpus = calloc((size_t)device_count, sizeof(*list->gpus));
		list->uuids = calloc((size_t)device_count, sizeof(*list->uuids));
		if (!list->gpu_values || !list->gpus || !list->uuids) {
			ret = -ENOMEM;
			goto out;
		}
	}

	for (int i = 0; i < device_count; i++) {
		if (api.get_uuid((CUuuid *)list->uuids[i], i) != CUDA_SUCCESS) {
			pr_err("cuDeviceGetUuid failed for CUDA device %d\n", i);
			ret = -1;
			goto out;
		}

		cuda_gpu__init(&list->gpu_values[i]);
		list->gpu_values[i].has_ordinal = 1;
		list->gpu_values[i].ordinal = i;
		list->gpu_values[i].has_uuid = 1;
		list->gpu_values[i].uuid.len = CUDA_GPU_UUID_SIZE;
		list->gpu_values[i].uuid.data = list->uuids[i];
		list->gpus[i] = &list->gpu_values[i];
	}

	list->inventory.has_version = 1;
	list->inventory.version = CUDA_GPU_INVENTORY_VERSION;
	list->inventory.n_gpus = (size_t)device_count;
	list->inventory.gpus = list->gpus;
	ret = 0;

out:
	cuda_device_api_fini(&api);
	cuda_restore_environment(&saved);
	if (ret)
		cuda_gpu_list_fini(list);
	return ret;
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
	struct cuda_gpu_list list = {};
	int ret;

	ret = cuda_enumerate_gpus(&list);
	if (ret)
		return ret;

	ret = cuda_write_inventory(&list.inventory);
	if (!ret)
		pr_info("Saved UUIDs for %zu CUDA GPUs\n", list.inventory.n_gpus);
	cuda_gpu_list_fini(&list);
	return ret;
}

static int cuda_uuid_compare(const void *left, const void *right)
{
	return memcmp(left, right, CUDA_GPU_UUID_SIZE);
}

static int cuda_validate_inventory(const CudaGpuInventory *inventory)
{
	unsigned char (*uuids)[CUDA_GPU_UUID_SIZE] = NULL;
	bool *seen = NULL;
	size_t i;
	int ret = -EINVAL;

	if (inventory->has_version && inventory->version != CUDA_GPU_INVENTORY_VERSION) {
		pr_err("Unsupported CUDA GPU inventory version %u\n", inventory->version);
		return -EINVAL;
	}
	if (!inventory->n_gpus || inventory->n_gpus > CUDA_GPU_INVENTORY_MAX_GPUS || !inventory->gpus) {
		pr_err("Invalid CUDA GPU inventory size %zu\n", inventory->n_gpus);
		return -EINVAL;
	}

	seen = calloc(inventory->n_gpus, sizeof(*seen));
	uuids = calloc(inventory->n_gpus, sizeof(*uuids));
	if (!seen || !uuids) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < inventory->n_gpus; i++) {
		const CudaGpu *gpu = inventory->gpus[i];

		if (!gpu || !gpu->has_ordinal || gpu->ordinal >= inventory->n_gpus ||
		    seen[gpu->ordinal] || !gpu->has_uuid || gpu->uuid.len != CUDA_GPU_UUID_SIZE ||
		    !gpu->uuid.data) {
			pr_err("Invalid CUDA GPU entry %zu in inventory\n", i);
			goto out;
		}

		seen[gpu->ordinal] = true;
		memcpy(uuids[i], gpu->uuid.data, CUDA_GPU_UUID_SIZE);
	}

	for (i = 0; i < inventory->n_gpus; i++) {
		if (!seen[i]) {
			pr_err("CUDA GPU inventory is missing ordinal %zu\n", i);
			goto out;
		}
	}

	qsort(uuids, inventory->n_gpus, sizeof(*uuids), cuda_uuid_compare);
	for (i = 1; i < inventory->n_gpus; i++) {
		if (!memcmp(uuids[i - 1], uuids[i], CUDA_GPU_UUID_SIZE)) {
			pr_err("Duplicate CUDA GPU UUID in inventory\n");
			goto out;
		}
	}

	ret = 0;
out:
	free(uuids);
	free(seen);
	return ret;
}

int cuda_gpu_inventory_restore_init(void)
{
	CudaGpuInventory *inventory;
	uint8_t *data;
	size_t size;
	int fd;
	int ret;

	cuda_gpu_inventory_fini();

	fd = cuda_open_inventory_image(false, &size);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0) {
		pr_err("Unable to open CUDA GPU inventory: %s\n", strerror(-fd));
		return fd;
	}
	if (!size || size > CUDA_GPU_INVENTORY_MAX_SIZE) {
		pr_err("Invalid CUDA GPU inventory image size %zu\n", size);
		close(fd);
		return -EINVAL;
	}

	data = malloc(size);
	if (!data) {
		close(fd);
		return -ENOMEM;
	}

	ret = cuda_img_read(fd, data, size);
	if (close(fd) && !ret)
		ret = -errno;
	if (ret) {
		free(data);
		return ret;
	}

	inventory = cuda_gpu_inventory__unpack(NULL, size, data);
	free(data);
	if (!inventory) {
		pr_err("Unable to unpack CUDA GPU inventory\n");
		return -EINVAL;
	}

	ret = cuda_validate_inventory(inventory);
	if (ret) {
		cuda_gpu_inventory__free_unpacked(inventory, NULL);
		return ret;
	}

	cuda_saved_inventory = inventory;
	pr_info("Loaded UUIDs for %zu checkpoint CUDA GPUs\n", inventory->n_gpus);
	return 0;
}

static int cuda_parse_uuid(const char *text, size_t length, unsigned char uuid[CUDA_GPU_UUID_SIZE])
{
	size_t i = 0;
	size_t digits = 0;

	if (length >= 4 && !memcmp(text, "GPU-", 4))
		i = 4;

	memset(uuid, 0, CUDA_GPU_UUID_SIZE);
	for (; i < length; i++) {
		int value;

		if (text[i] == '-')
			continue;
		if (text[i] >= '0' && text[i] <= '9')
			value = text[i] - '0';
		else if (text[i] >= 'a' && text[i] <= 'f')
			value = text[i] - 'a' + 10;
		else if (text[i] >= 'A' && text[i] <= 'F')
			value = text[i] - 'A' + 10;
		else
			return -EINVAL;

		if (digits >= CUDA_GPU_UUID_SIZE * 2)
			return -EINVAL;
		if (!(digits & 1))
			uuid[digits / 2] = (unsigned char)(value << 4);
		else
			uuid[digits / 2] |= (unsigned char)value;
		digits++;
	}

	return digits == CUDA_GPU_UUID_SIZE * 2 ? 0 : -EINVAL;
}

static int cuda_parse_index(const char *text, size_t length, unsigned int *index)
{
	uint64_t value = 0;

	if (!length)
		return -EINVAL;

	for (size_t i = 0; i < length; i++) {
		uint64_t digit;

		if (text[i] < '0' || text[i] > '9')
			return -EINVAL;
		digit = (uint64_t)(text[i] - '0');
		if (value > (UINT_MAX - digit) / 10)
			return -ERANGE;
		value = value * 10 + digit;
	}

	*index = (unsigned int)value;
	return 0;
}

static int cuda_parse_map_token(const char *text, size_t length, bool *is_index,
				unsigned int *index, unsigned char uuid[CUDA_GPU_UUID_SIZE])
{
	bool decimal = true;

	if (!length)
		return -EINVAL;

	for (size_t i = 0; i < length; i++) {
		if (text[i] < '0' || text[i] > '9') {
			decimal = false;
			break;
		}
	}

	/* A 32-digit decimal string is treated as a UUID, not as an ordinal. */
	if (decimal && length < CUDA_GPU_UUID_SIZE * 2) {
		int ret = cuda_parse_index(text, length, index);

		if (!ret)
			*is_index = true;
		return ret;
	}

	*is_index = false;
	return cuda_parse_uuid(text, length, uuid);
}

static const CudaGpu *cuda_inventory_gpu_at(const CudaGpuInventory *inventory, unsigned int ordinal)
{
	for (size_t i = 0; i < inventory->n_gpus; i++) {
		if (inventory->gpus[i]->ordinal == ordinal)
			return inventory->gpus[i];
	}

	return NULL;
}

static int cuda_inventory_find_uuid(const CudaGpuInventory *inventory,
				   const unsigned char uuid[CUDA_GPU_UUID_SIZE], unsigned int *ordinal)
{
	for (size_t i = 0; i < inventory->n_gpus; i++) {
		if (!memcmp(inventory->gpus[i]->uuid.data, uuid, CUDA_GPU_UUID_SIZE)) {
			*ordinal = inventory->gpus[i]->ordinal;
			return 0;
		}
	}

	return -ENOENT;
}

static int cuda_build_automatic_map(CUcheckpointGpuPair **pairs_out, unsigned int *count_out)
{
	struct cuda_gpu_list destination = {};
	CUcheckpointGpuPair *pairs;
	size_t source_count;
	int ret;

	if (!cuda_saved_inventory) {
		pr_err("CUDA device-map=auto requires a saved GPU inventory\n");
		return -EINVAL;
	}

	source_count = cuda_saved_inventory->n_gpus;
	if (source_count > UINT_MAX)
		return -E2BIG;

	ret = cuda_enumerate_gpus(&destination);
	if (ret)
		return ret;
	if (destination.inventory.n_gpus < source_count) {
		pr_err("CUDA device-map=auto needs at least %zu destination GPUs, found %zu\n",
		       source_count, destination.inventory.n_gpus);
		cuda_gpu_list_fini(&destination);
		return -EINVAL;
	}

	pairs = calloc(source_count, sizeof(*pairs));
	if (!pairs) {
		cuda_gpu_list_fini(&destination);
		return -ENOMEM;
	}

	for (unsigned int i = 0; i < source_count; i++) {
		const CudaGpu *source = cuda_inventory_gpu_at(cuda_saved_inventory, i);
		const CudaGpu *target = cuda_inventory_gpu_at(&destination.inventory, i);

		memcpy(pairs[i].oldUuid, source->uuid.data, CUDA_GPU_UUID_SIZE);
		memcpy(pairs[i].newUuid, target->uuid.data, CUDA_GPU_UUID_SIZE);
	}

	*pairs_out = pairs;
	*count_out = (unsigned int)source_count;
	cuda_gpu_list_fini(&destination);
	return 0;
}

int cuda_get_device_map(CUcheckpointGpuPair **pairs_out, unsigned int *count_out)
{
	const char *map;
	struct cuda_gpu_list destination = {};
	CUcheckpointGpuPair *pairs = NULL;
	bool *source_seen = NULL;
	bool destination_ready = false;
	size_t entry_count = 1;
	unsigned int i;
	const char *entry;
	int ret;

	*pairs_out = NULL;
	*count_out = 0;

	ret = criu_plugin_get_option("cuda", "device-map", &map);
	if (ret == -ENOENT)
		return 0;
	if (ret) {
		pr_err("Unable to read CUDA device map option: %d\n", ret);
		return ret;
	}
	if (!map || !map[0]) {
		pr_err("CUDA device-map cannot be empty\n");
		return -EINVAL;
	}

	if (!strcmp(map, "auto"))
		return cuda_build_automatic_map(pairs_out, count_out);

	for (const char *cursor = map; *cursor; cursor++) {
		if (*cursor == ',') {
			if (entry_count == SIZE_MAX)
				return -EOVERFLOW;
			entry_count++;
		}
	}
	if (entry_count > UINT_MAX) {
		pr_err("Too many CUDA device mappings\n");
		return -E2BIG;
	}
	if (cuda_saved_inventory && entry_count != cuda_saved_inventory->n_gpus) {
		pr_err("CUDA device map must specify all %zu checkpoint GPUs\n",
		       cuda_saved_inventory->n_gpus);
		return -EINVAL;
	}

	pairs = calloc(entry_count, sizeof(*pairs));
	if (!pairs)
		return -ENOMEM;
	if (cuda_saved_inventory) {
		source_seen = calloc(cuda_saved_inventory->n_gpus, sizeof(*source_seen));
		if (!source_seen) {
			ret = -ENOMEM;
			goto out;
		}
	}

	entry = map;
	for (i = 0;; i++) {
		const char *comma = strchr(entry, ',');
		size_t entry_length = comma ? (size_t)(comma - entry) : strlen(entry);
		const char *equal;
		size_t left_length;
		size_t right_length;
		unsigned char source_uuid[CUDA_GPU_UUID_SIZE];
		unsigned char destination_uuid[CUDA_GPU_UUID_SIZE];
		unsigned int source_ordinal = 0;
		unsigned int destination_ordinal = 0;
		bool source_index;
		bool destination_index;
		const CudaGpu *source_gpu;
		const CudaGpu *destination_gpu;

		if (!entry_length) {
			pr_err("Invalid empty CUDA device mapping\n");
			ret = -EINVAL;
			goto out;
		}
		equal = memchr(entry, '=', entry_length);
		if (!equal || equal == entry || equal == entry + entry_length - 1 ||
		    memchr(equal + 1, '=', entry_length - (size_t)(equal - entry) - 1)) {
			pr_err("Invalid CUDA device mapping; expected source=destination\n");
			ret = -EINVAL;
			goto out;
		}

		left_length = (size_t)(equal - entry);
		right_length = entry_length - left_length - 1;
		ret = cuda_parse_map_token(entry, left_length, &source_index, &source_ordinal, source_uuid);
		if (ret) {
			pr_err("Invalid source in CUDA device mapping %u\n", i);
			goto out;
		}
		ret = cuda_parse_map_token(equal + 1, right_length, &destination_index,
					   &destination_ordinal, destination_uuid);
		if (ret) {
			pr_err("Invalid destination in CUDA device mapping %u\n", i);
			goto out;
		}

		if (source_index) {
			if (!cuda_saved_inventory) {
				pr_err("Numeric CUDA source mappings require a saved GPU inventory\n");
				ret = -EINVAL;
				goto out;
			}
			if (source_ordinal >= cuda_saved_inventory->n_gpus) {
				pr_err("CUDA source GPU ordinal %u is out of range\n", source_ordinal);
				ret = -EINVAL;
				goto out;
			}
			source_gpu = cuda_inventory_gpu_at(cuda_saved_inventory, source_ordinal);
			memcpy(source_uuid, source_gpu->uuid.data, CUDA_GPU_UUID_SIZE);
		} else if (cuda_saved_inventory) {
			ret = cuda_inventory_find_uuid(cuda_saved_inventory, source_uuid, &source_ordinal);
			if (ret) {
				pr_err("CUDA source GPU UUID is not present in the checkpoint inventory\n");
				goto out;
			}
			source_gpu = cuda_inventory_gpu_at(cuda_saved_inventory, source_ordinal);
		} else {
			source_gpu = NULL;
		}

		if (cuda_saved_inventory) {
			if (source_seen[source_ordinal]) {
				pr_err("CUDA source GPU %u is mapped more than once\n", source_ordinal);
				ret = -EINVAL;
				goto out;
			}
			source_seen[source_ordinal] = true;
		} else {
			for (unsigned int previous = 0; previous < i; previous++) {
				if (!memcmp(pairs[previous].oldUuid, source_uuid, CUDA_GPU_UUID_SIZE)) {
					pr_err("CUDA source GPU UUID is mapped more than once\n");
					ret = -EINVAL;
					goto out;
				}
			}
		}

		if (destination_index) {
			if (!destination_ready) {
				ret = cuda_enumerate_gpus(&destination);
				if (ret)
					goto out;
				destination_ready = true;
			}
			if (destination_ordinal >= destination.inventory.n_gpus) {
				pr_err("CUDA destination GPU ordinal %u is out of range\n", destination_ordinal);
				ret = -EINVAL;
				goto out;
			}
			destination_gpu = cuda_inventory_gpu_at(&destination.inventory, destination_ordinal);
			memcpy(destination_uuid, destination_gpu->uuid.data, CUDA_GPU_UUID_SIZE);
		}

		memcpy(pairs[i].oldUuid, source_uuid, CUDA_GPU_UUID_SIZE);
		memcpy(pairs[i].newUuid, destination_uuid, CUDA_GPU_UUID_SIZE);

		if (!comma)
			break;
		entry = comma + 1;
	}

	if (cuda_saved_inventory) {
		for (size_t ordinal = 0; ordinal < cuda_saved_inventory->n_gpus; ordinal++) {
			if (!source_seen[ordinal]) {
				pr_err("CUDA device map is missing checkpoint GPU %zu\n", ordinal);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	*pairs_out = pairs;
	*count_out = (unsigned int)entry_count;
	pairs = NULL;
	ret = 0;

out:
	free(source_seen);
	free(pairs);
	cuda_gpu_list_fini(&destination);
	return ret;
}

void cuda_free_device_map(CUcheckpointGpuPair *pairs)
{
	free(pairs);
}
