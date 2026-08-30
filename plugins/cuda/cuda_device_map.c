#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cuda_device_map.h"
#include "cuda.pb-c.h"
#include "criu-plugin.h"
#include "criu-log.h"
#include "cr_options.h"
#include "image.h"
#include "img-streamer.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

#define CUDA_GPU_INVENTORY_IMAGE    "cuda-gpu-inventory.img"
#define CUDA_GPU_UUID_SIZE	    16
#define CUDA_GPU_INVENTORY_VERSION  1
#define CUDA_GPU_INVENTORY_MAX_SIZE (16 * 1024 * 1024)
#define CUDA_GPU_INVENTORY_MAX_GPUS 65536
#define CUDA_GPU_UUID_TEXT_SIZE	    40
#define CUDA_GPU_PAIR_TEXT_SIZE	    (CUDA_GPU_UUID_TEXT_SIZE * 2 + 1)

_Static_assert(sizeof(CUcheckpointGpuPair) == 32,
	       "CUcheckpointGpuPair must be 32 bytes");
_Static_assert(offsetof(CUcheckpointGpuPair, oldUuid) == 0,
	       "CUcheckpointGpuPair.oldUuid has an unexpected offset");
_Static_assert(offsetof(CUcheckpointGpuPair, newUuid) == CUDA_GPU_UUID_SIZE,
	       "CUcheckpointGpuPair.newUuid has an unexpected offset");

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

struct cuda_gpu_list {
	CudaGpuInventory inventory;
	CudaGpu *gpu_values;
	CudaGpu **gpus;
	unsigned char (*uuids)[CUDA_GPU_UUID_SIZE];
};

enum cuda_map_token_type {
	CUDA_MAP_TOKEN_UUID,
	CUDA_MAP_TOKEN_ORDINAL,
};

struct cuda_map_token {
	enum cuda_map_token_type type;
	unsigned int ordinal;
	unsigned char uuid[CUDA_GPU_UUID_SIZE];
};

static CudaGpuInventory *cuda_saved_inventory;

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
		len -= (size_t)ret;
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
		len -= (size_t)ret;
	}

	return 0;
}

static int cuda_img_at_eof(int fd)
{
	unsigned char byte;
	ssize_t ret;

	do {
		ret = read(fd, &byte, sizeof(byte));
	} while (ret < 0 && (errno == EINTR || errno == EAGAIN));

	if (ret < 0)
		return -errno;
	if (ret > 0)
		return -EINVAL;
	return 0;
}

static int cuda_open_inventory_image(bool write_image, size_t *size)
{
	uint32_t image_size;
	int flags;
	int fd;
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
		return -ENODEV;
	}

	api->init = (cuda_init_fn)cuda_get_symbol(api->handle, "cuInit");
	api->get_count = (cuda_device_get_count_fn)cuda_get_symbol(api->handle, "cuDeviceGetCount");
	api->get_uuid = (cuda_device_get_uuid_fn)cuda_get_symbol(api->handle, "cuDeviceGetUuid");
	if (!api->init || !api->get_count || !api->get_uuid) {
		cuda_device_api_fini(api);
		return -ENOSYS;
	}

	return 0;
}

static void cuda_gpu_list_fini(struct cuda_gpu_list *list)
{
	free(list->gpu_values);
	free(list->gpus);
	free(list->uuids);
	memset(list, 0, sizeof(*list));
}

static int cuda_validate_inventory(const CudaGpuInventory *inventory);

static int cuda_gpu_list_init(struct cuda_gpu_list *list, unsigned int count)
{
	unsigned int i;

	memset(list, 0, sizeof(*list));
	cuda_gpu_inventory__init(&list->inventory);
	list->gpu_values = calloc(count, sizeof(*list->gpu_values));
	list->gpus = calloc(count, sizeof(*list->gpus));
	list->uuids = calloc(count, sizeof(*list->uuids));
	if (!list->gpu_values || !list->gpus || !list->uuids) {
		cuda_gpu_list_fini(list);
		return -ENOMEM;
	}

	for (i = 0; i < count; i++) {
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
	list->inventory.n_gpus = count;
	list->inventory.gpus = list->gpus;
	return 0;
}

/* Only the short-lived enumeration child may initialize CUDA. */
static int cuda_collect_gpus(struct cuda_gpu_list *list)
{
	struct cuda_device_api api = {};
	int device_count;
	int ret;
	int i;

	ret = cuda_device_api_init(&api);
	if (ret)
		goto out;

	if (api.init(0) != CUDA_SUCCESS) {
		pr_err("cuInit failed while collecting CUDA GPU inventory\n");
		ret = -EIO;
		goto out;
	}
	if (api.get_count(&device_count) != CUDA_SUCCESS || device_count <= 0) {
		pr_err("cuDeviceGetCount failed while collecting CUDA GPU inventory\n");
		ret = -EIO;
		goto out;
	}
	if ((unsigned int)device_count > CUDA_GPU_INVENTORY_MAX_GPUS) {
		pr_err("Too many CUDA GPUs to save in the inventory: %d\n", device_count);
		ret = -E2BIG;
		goto out;
	}

	ret = cuda_gpu_list_init(list, (unsigned int)device_count);
	if (ret)
		goto out;

	for (i = 0; i < device_count; i++) {
		if (api.get_uuid((CUuuid *)list->uuids[i], i) != CUDA_SUCCESS) {
			pr_err("cuDeviceGetUuid failed for CUDA device %d\n", i);
			ret = -EIO;
			goto out;
		}
	}

out:
	cuda_device_api_fini(&api);
	if (ret)
		cuda_gpu_list_fini(list);
	return ret;
}

static int cuda_enumerate_gpus(struct cuda_gpu_list *list)
{
	struct {
		int error;
		unsigned int count;
	} reply = {};
	sigset_t mask, saved_mask;
	int pipefd[2];
	pid_t child, waited;
	int status;
	int ret;

	memset(list, 0, sizeof(*list));
	if (pipe2(pipefd, O_CLOEXEC))
		return -errno;

	/* Keep CRIU's SIGCHLD handler from reaping the enumeration helper. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, &saved_mask)) {
		ret = -errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return ret;
	}

	/*
	 * cuInit() can leave a driver thread sharing our fs_struct. In the
	 * restore parent that would prevent later setns(CLONE_NEWNS) calls.
	 * Collect only UUIDs in a child; all image and streamer I/O stays here.
	 */
	child = fork();
	if (child == 0) {
		close(pipefd[0]);
		reply.error = cuda_collect_gpus(list);
		if (!reply.error)
			reply.count = (unsigned int)list->inventory.n_gpus;
		ret = cuda_img_write(pipefd[1], &reply, sizeof(reply));
		if (!ret && !reply.error)
			ret = cuda_img_write(pipefd[1], list->uuids,
					     reply.count * sizeof(*list->uuids));
		cuda_gpu_list_fini(list);
		close(pipefd[1]);
		_exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	ret = child < 0 ? -errno : 0;
	close(pipefd[1]);
	if (ret) {
		close(pipefd[0]);
		goto restore_mask;
	}

	ret = cuda_img_read(pipefd[0], &reply, sizeof(reply));
	if (!ret && reply.error)
		ret = reply.error < 0 ? reply.error : -EIO;
	if (!ret && (!reply.count || reply.count > CUDA_GPU_INVENTORY_MAX_GPUS))
		ret = -EINVAL;
	if (!ret)
		ret = cuda_gpu_list_init(list, reply.count);
	if (!ret)
		ret = cuda_img_read(pipefd[0], list->uuids, reply.count * sizeof(*list->uuids));
	if (!ret)
		ret = cuda_img_at_eof(pipefd[0]);
	close(pipefd[0]);

	if (ret)
		kill(child, SIGKILL);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (!ret && waited < 0)
		ret = -errno;
	if (!ret && (!WIFEXITED(status) || WEXITSTATUS(status)))
		ret = -EIO;
	if (!ret)
		ret = cuda_validate_inventory(&list->inventory);

restore_mask:
	if (sigprocmask(SIG_SETMASK, &saved_mask, NULL) && !ret)
		ret = -errno;
	if (ret)
		cuda_gpu_list_fini(list);
	return ret;
}

static int cuda_write_inventory(const CudaGpuInventory *inventory)
{
	uint8_t *data;
	size_t size;
	int fd;
	int ret;

	size = cuda_gpu_inventory__get_packed_size(inventory);
	if (!size || size > CUDA_GPU_INVENTORY_MAX_SIZE)
		return -E2BIG;

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

void cuda_gpu_inventory_fini(void)
{
	if (cuda_saved_inventory)
		cuda_gpu_inventory__free_unpacked(cuda_saved_inventory, NULL);
	cuda_saved_inventory = NULL;
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
	if (!inventory->n_gpus || inventory->n_gpus > CUDA_GPU_INVENTORY_MAX_GPUS ||
	    !inventory->gpus) {
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
		    seen[gpu->ordinal] || !gpu->has_uuid ||
		    gpu->uuid.len != CUDA_GPU_UUID_SIZE || !gpu->uuid.data) {
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
	size_t size = 0;
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
	if (!ret)
		ret = cuda_img_at_eof(fd);
	if (close(fd) && !ret)
		ret = -errno;
	if (ret) {
		if (ret == -EINVAL)
			pr_err("CUDA GPU inventory contains trailing data\n");
		else
			pr_err("Unable to read CUDA GPU inventory: %s\n", strerror(-ret));
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

static int cuda_parse_uuid(const char *text, size_t length,
			   unsigned char uuid[CUDA_GPU_UUID_SIZE])
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

static int cuda_parse_ordinal(const char *text, size_t length, unsigned int *ordinal)
{
	uint64_t value = 0;
	size_t i;

	if (!length)
		return -EINVAL;

	for (i = 0; i < length; i++) {
		uint64_t digit;

		if (text[i] < '0' || text[i] > '9')
			return -EINVAL;
		digit = (uint64_t)(text[i] - '0');
		if (value > (UINT_MAX - digit) / 10)
			return -ERANGE;
		value = value * 10 + digit;
	}

	*ordinal = (unsigned int)value;
	return 0;
}

static int cuda_parse_map_token(const char *text, size_t length,
				struct cuda_map_token *token)
{
	bool decimal = true;
	size_t i;

	if (!length)
		return -EINVAL;

	for (i = 0; i < length; i++) {
		if (text[i] < '0' || text[i] > '9') {
			decimal = false;
			break;
		}
	}

	/* A 32-digit decimal string is a UUID, not an ordinal. */
	if (decimal && length < CUDA_GPU_UUID_SIZE * 2) {
		token->type = CUDA_MAP_TOKEN_ORDINAL;
		return cuda_parse_ordinal(text, length, &token->ordinal);
	}

	token->type = CUDA_MAP_TOKEN_UUID;
	return cuda_parse_uuid(text, length, token->uuid);
}

static int cuda_parse_map_entry(const char *entry, size_t length,
				struct cuda_map_token *source,
				struct cuda_map_token *destination)
{
	const char *equal;
	size_t left_length;
	size_t right_length;
	int ret;

	if (!length)
		return -EINVAL;

	equal = memchr(entry, '=', length);
	if (!equal || equal == entry || equal == entry + length - 1 ||
	    memchr(equal + 1, '=', length - (size_t)(equal - entry) - 1))
		return -EINVAL;

	left_length = (size_t)(equal - entry);
	right_length = length - left_length - 1;
	ret = cuda_parse_map_token(entry, left_length, source);
	if (ret)
		return ret;
	return cuda_parse_map_token(equal + 1, right_length, destination);
}

static int cuda_count_map_entries(const char *value, unsigned int *count)
{
	const char *entry = value;
	unsigned int nr = 0;

	for (;;) {
		const char *comma = strchr(entry, ',');
		size_t length = comma ? (size_t)(comma - entry) : strlen(entry);

		if (!length)
			return -EINVAL;
		if (nr == CUDA_GPU_INVENTORY_MAX_GPUS)
			return -E2BIG;
		nr++;

		if (!comma)
			break;
		entry = comma + 1;
	}

	*count = nr;
	return 0;
}

int cuda_device_map_validate(const char *value)
{
	const char *entry;
	unsigned int count;
	unsigned int index = 0;
	int ret;

	if (!value)
		return 0;
	if (!value[0]) {
		pr_err("CUDA device-map cannot be empty\n");
		return -EINVAL;
	}
	if (!strcmp(value, "auto"))
		return 0;

	ret = cuda_count_map_entries(value, &count);
	if (ret) {
		pr_err("Invalid CUDA device map\n");
		return ret;
	}

	entry = value;
	while (index < count) {
		struct cuda_map_token source = {};
		struct cuda_map_token destination = {};
		const char *comma = strchr(entry, ',');
		size_t length = comma ? (size_t)(comma - entry) : strlen(entry);

		ret = cuda_parse_map_entry(entry, length, &source, &destination);
		if (ret) {
			pr_err("Invalid CUDA device mapping %u; expected source=destination with UUIDs or ordinals\n",
			       index);
			return ret;
		}

		index++;
		if (!comma)
			break;
		entry = comma + 1;
	}

	return 0;
}

static const CudaGpu *cuda_inventory_gpu_at(const CudaGpuInventory *inventory,
					    unsigned int ordinal)
{
	size_t i;

	for (i = 0; i < inventory->n_gpus; i++) {
		if (inventory->gpus[i]->ordinal == ordinal)
			return inventory->gpus[i];
	}

	return NULL;
}

static int cuda_inventory_find_uuid(const CudaGpuInventory *inventory,
				    const unsigned char uuid[CUDA_GPU_UUID_SIZE],
				    unsigned int *ordinal)
{
	size_t i;

	for (i = 0; i < inventory->n_gpus; i++) {
		if (!memcmp(inventory->gpus[i]->uuid.data, uuid, CUDA_GPU_UUID_SIZE)) {
			*ordinal = inventory->gpus[i]->ordinal;
			return 0;
		}
	}

	return -ENOENT;
}

static char *cuda_format_uuid(char *output,
			      const unsigned char uuid[CUDA_GPU_UUID_SIZE])
{
	static const char digits[] = "0123456789abcdef";
	unsigned int i;

	memcpy(output, "GPU-", 4);
	output += 4;
	for (i = 0; i < CUDA_GPU_UUID_SIZE; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			*output++ = '-';
		*output++ = digits[uuid[i] >> 4];
		*output++ = digits[uuid[i] & 0xf];
	}

	return output;
}

static int cuda_build_cli_value(struct cuda_device_map *map)
{
	size_t size;
	char *cursor;
	unsigned int i;

	if (!map->count)
		return 0;
	if (__builtin_mul_overflow((size_t)map->count,
				   (size_t)(CUDA_GPU_PAIR_TEXT_SIZE + 1), &size))
		return -EOVERFLOW;

	map->cli_value = malloc(size);
	if (!map->cli_value)
		return -ENOMEM;

	cursor = map->cli_value;
	for (i = 0; i < map->count; i++) {
		if (i)
			*cursor++ = ',';
		cursor = cuda_format_uuid(cursor, map->pairs[i].oldUuid);
		*cursor++ = '=';
		cursor = cuda_format_uuid(cursor, map->pairs[i].newUuid);
	}
	*cursor = '\0';

	return 0;
}

static int cuda_validate_unique_map_uuids(const struct cuda_device_map *map)
{
	unsigned char (*uuids)[CUDA_GPU_UUID_SIZE];
	unsigned int i;
	unsigned int side;

	uuids = malloc((size_t)map->count * sizeof(*uuids));
	if (!uuids)
		return -ENOMEM;

	for (side = 0; side < 2; side++) {
		for (i = 0; i < map->count; i++) {
			const unsigned char *uuid;

			uuid = side ? map->pairs[i].newUuid : map->pairs[i].oldUuid;

			memcpy(uuids[i], uuid, CUDA_GPU_UUID_SIZE);
		}

		qsort(uuids, map->count, sizeof(*uuids), cuda_uuid_compare);
		for (i = 1; i < map->count; i++) {
			if (!memcmp(uuids[i - 1], uuids[i], CUDA_GPU_UUID_SIZE)) {
				pr_err("CUDA %s GPU UUID is mapped more than once\n",
				       side ? "destination" : "source");
				free(uuids);
				return -EINVAL;
			}
		}
	}

	free(uuids);
	return 0;
}

void cuda_device_map_fini(struct cuda_device_map *map)
{
	free(map->pairs);
	free(map->cli_value);
	memset(map, 0, sizeof(*map));
}

static int cuda_build_automatic_map(struct cuda_device_map *map)
{
	struct cuda_gpu_list destination = {};
	size_t source_count;
	unsigned int i;
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
		ret = -EINVAL;
		goto out;
	}

	map->pairs = calloc(source_count, sizeof(*map->pairs));
	if (!map->pairs) {
		ret = -ENOMEM;
		goto out;
	}
	map->count = (unsigned int)source_count;

	for (i = 0; i < map->count; i++) {
		const CudaGpu *source = cuda_inventory_gpu_at(cuda_saved_inventory, i);
		const CudaGpu *target = cuda_inventory_gpu_at(&destination.inventory, i);

		memcpy(map->pairs[i].oldUuid, source->uuid.data, CUDA_GPU_UUID_SIZE);
		memcpy(map->pairs[i].newUuid, target->uuid.data, CUDA_GPU_UUID_SIZE);
	}

	ret = cuda_build_cli_value(map);
out:
	cuda_gpu_list_fini(&destination);
	if (ret)
		cuda_device_map_fini(map);
	return ret;
}

/*
 * Resolve CRIU's device-map syntax to UUID pairs for the Driver API and the
 * equivalent UUID mapping string for cuda-checkpoint. CUDA requires a mapping
 * for every GPU visible to the checkpointed process, including unused GPUs.
 * With a saved inventory, require each source GPU exactly once and reject
 * duplicate destination UUIDs. GPUs that stay in place also need identity mappings.
 *
 * GPU numbers (e.g., 0=1) refer to the saved source GPU list and the current
 * destination list. "auto" maps GPUs with the same number. Without a saved
 * list, only UUID mappings are accepted.
 */
int cuda_device_map_resolve(const char *value, struct cuda_device_map *map)
{
	struct cuda_gpu_list destination = {};
	bool destination_ready = false;
	bool *source_seen = NULL;
	const char *entry;
	unsigned int entry_count;
	unsigned int i;
	int ret;

	memset(map, 0, sizeof(*map));
	ret = cuda_device_map_validate(value);
	if (ret || !value)
		return ret;
	if (!strcmp(value, "auto"))
		return cuda_build_automatic_map(map);

	ret = cuda_count_map_entries(value, &entry_count);
	if (ret)
		return ret;
	if (cuda_saved_inventory && entry_count != cuda_saved_inventory->n_gpus) {
		pr_err("CUDA device map must specify all %zu checkpoint GPUs\n",
		       cuda_saved_inventory->n_gpus);
		return -EINVAL;
	}

	map->pairs = calloc(entry_count, sizeof(*map->pairs));
	if (!map->pairs)
		return -ENOMEM;
	map->count = entry_count;

	if (cuda_saved_inventory) {
		source_seen = calloc(cuda_saved_inventory->n_gpus, sizeof(*source_seen));
		if (!source_seen) {
			ret = -ENOMEM;
			goto out;
		}
	}

	entry = value;
	for (i = 0; i < entry_count; i++) {
		struct cuda_map_token source = {};
		struct cuda_map_token target = {};
		const CudaGpu *gpu;
		const char *comma = strchr(entry, ',');
		size_t length = comma ? (size_t)(comma - entry) : strlen(entry);
		unsigned int source_ordinal = 0;

		ret = cuda_parse_map_entry(entry, length, &source, &target);
		if (ret)
			goto out;

		if (!cuda_saved_inventory &&
		    (source.type == CUDA_MAP_TOKEN_ORDINAL || target.type == CUDA_MAP_TOKEN_ORDINAL)) {
			pr_err("Numeric CUDA mappings require a saved GPU inventory\n");
			ret = -EINVAL;
			goto out;
		}

		if (source.type == CUDA_MAP_TOKEN_ORDINAL) {
			source_ordinal = source.ordinal;
			if (source_ordinal >= cuda_saved_inventory->n_gpus) {
				pr_err("CUDA source GPU ordinal %u is out of range\n", source_ordinal);
				ret = -EINVAL;
				goto out;
			}
			gpu = cuda_inventory_gpu_at(cuda_saved_inventory, source_ordinal);
			memcpy(source.uuid, gpu->uuid.data, CUDA_GPU_UUID_SIZE);
		} else if (cuda_saved_inventory) {
			ret = cuda_inventory_find_uuid(cuda_saved_inventory, source.uuid,
						       &source_ordinal);
			if (ret) {
				pr_err("CUDA source GPU UUID is not present in the checkpoint inventory\n");
				ret = -EINVAL;
				goto out;
			}
		}

		if (cuda_saved_inventory) {
			if (source_seen[source_ordinal]) {
				pr_err("CUDA source GPU %u is mapped more than once\n", source_ordinal);
				ret = -EINVAL;
				goto out;
			}
			source_seen[source_ordinal] = true;
		}

		if (target.type == CUDA_MAP_TOKEN_ORDINAL) {
			if (!destination_ready) {
				ret = cuda_enumerate_gpus(&destination);
				if (ret)
					goto out;
				destination_ready = true;
			}
			if (target.ordinal >= destination.inventory.n_gpus) {
				pr_err("CUDA destination GPU ordinal %u is out of range\n",
				       target.ordinal);
				ret = -EINVAL;
				goto out;
			}
			gpu = cuda_inventory_gpu_at(&destination.inventory, target.ordinal);
			memcpy(target.uuid, gpu->uuid.data, CUDA_GPU_UUID_SIZE);
		}

		memcpy(map->pairs[i].oldUuid, source.uuid, CUDA_GPU_UUID_SIZE);
		memcpy(map->pairs[i].newUuid, target.uuid, CUDA_GPU_UUID_SIZE);

		if (comma)
			entry = comma + 1;
	}

	ret = cuda_validate_unique_map_uuids(map);
	if (ret)
		goto out;

	ret = cuda_build_cli_value(map);
out:
	free(source_seen);
	cuda_gpu_list_fini(&destination);
	if (ret)
		cuda_device_map_fini(map);
	return ret;
}
