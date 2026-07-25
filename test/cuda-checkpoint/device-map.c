#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cr_options.h"
#include "criu-log.h"
#include "cuda_device_map.h"

#define MOCK_GPU_COUNT 4
#define CUDA_UUID_SIZE 16
#define CUDA_GPU_INVENTORY_IMAGE "cuda-gpu-inventory.img"

struct cr_options opts;

static const char *device_map_option;
static int image_dir_fd = -1;
static const char uuid_map[] =
	"GPU-00010203-0405-0607-0809-0a0b0c0d0e0f="
	"GPU-50515253-5455-5657-5859-5a5b5c5d5e5f,"
	"GPU-10111213-1415-1617-1819-1a1b1c1d1e1f="
	"GPU-40414243-4445-4647-4849-4a4b4c4d4e4f,"
	"GPU-20212223-2425-2627-2829-2a2b2c2d2e2f="
	"GPU-60616263-6465-6667-6869-6a6b6c6d6e6f,"
	"GPU-30313233-3435-3637-3839-3a3b3c3d3e3f="
	"GPU-70717273-7475-7677-7879-7a7b7c7d7e7f";

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	(void)loglevel;
	(void)format;
}

int criu_get_image_dir(void)
{
	return image_dir_fd;
}

int criu_plugin_get_option(const char *plugin, const char *name, const char **value)
{
	assert(!strcmp(plugin, "cuda"));
	assert(!strcmp(name, "device-map"));
	assert(value);

	*value = NULL;
	if (!device_map_option)
		return -ENOENT;

	*value = device_map_option;
	return 0;
}

int img_streamer_open(char *filename, int flags)
{
	(void)filename;
	(void)flags;
	assert(0);
	return -EIO;
}

static void expected_uuid(unsigned char uuid[CUDA_UUID_SIZE], unsigned int device, unsigned int offset)
{
	unsigned int i;

	for (i = 0; i < CUDA_UUID_SIZE; i++)
		uuid[i] = (unsigned char)(offset + device * CUDA_UUID_SIZE + i);
}

static void check_pair(const CUcheckpointGpuPair *pair, unsigned int source, unsigned int destination)
{
	unsigned char source_uuid[CUDA_UUID_SIZE];
	unsigned char destination_uuid[CUDA_UUID_SIZE];

	expected_uuid(source_uuid, source, 0);
	expected_uuid(destination_uuid, destination, 64);
	assert(!memcmp(pair->oldUuid, source_uuid, sizeof(source_uuid)));
	assert(!memcmp(pair->newUuid, destination_uuid, sizeof(destination_uuid)));
}

static void check_no_map(void)
{
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 1;

	device_map_option = NULL;
	assert(cuda_get_device_map(&pairs, &count) == 0);
	assert(!pairs);
	assert(count == 0);
}

static void check_numeric_map(void)
{
	static const unsigned int destinations[MOCK_GPU_COUNT] = { 1, 0, 2, 3 };
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 0;
	unsigned int i;

	device_map_option = "0=1,1=0,2=2,3=3";
	assert(cuda_get_device_map(&pairs, &count) == 0);
	assert(count == MOCK_GPU_COUNT);
	for (i = 0; i < count; i++)
		check_pair(&pairs[i], i, destinations[i]);

	cuda_free_device_map(pairs);
}

static void check_automatic_map(void)
{
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 0;
	unsigned int i;

	device_map_option = "auto";
	assert(cuda_get_device_map(&pairs, &count) == 0);
	assert(count == MOCK_GPU_COUNT);
	for (i = 0; i < count; i++)
		check_pair(&pairs[i], i, i);

	cuda_free_device_map(pairs);
}

static void check_uuid_map(const char *uuid_map)
{
	static const unsigned int destinations[MOCK_GPU_COUNT] = { 1, 0, 2, 3 };
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 0;
	unsigned int i;

	device_map_option = uuid_map;
	assert(cuda_get_device_map(&pairs, &count) == 0);
	assert(count == MOCK_GPU_COUNT);
	for (i = 0; i < count; i++)
		check_pair(&pairs[i], i, destinations[i]);

	cuda_free_device_map(pairs);
}

static void check_invalid_maps(void)
{
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 0;

	device_map_option = "0=1";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);
	device_map_option = "0=1,0=0,2=2,3=3";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);
	device_map_option = "0=1,1=0,2=2,3";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);
	device_map_option = "";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);
}

static void check_without_inventory(const char *uuid_map)
{
	CUcheckpointGpuPair *pairs = NULL;
	unsigned int count = 0;

	cuda_gpu_inventory_fini();
	assert(unlinkat(image_dir_fd, CUDA_GPU_INVENTORY_IMAGE, 0) == 0);
	assert(cuda_gpu_inventory_restore_init() == 0);

	device_map_option = "0=1,1=0,2=2,3=3";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);
	device_map_option = "auto";
	assert(cuda_get_device_map(&pairs, &count) == -EINVAL);

	device_map_option = uuid_map;
	assert(cuda_get_device_map(&pairs, &count) == 0);
	assert(count == MOCK_GPU_COUNT);
	cuda_free_device_map(pairs);

	check_no_map();
}

int main(void)
{
	char directory[] = "/tmp/criu-cuda-device-map.XXXXXX";
	const char *visible_devices = "3,2,1,0";
	const char *device_order = "PCI_BUS_ID";

	assert(mkdtemp(directory));
	image_dir_fd = open(directory, O_RDONLY | O_DIRECTORY);
	assert(image_dir_fd >= 0);

	assert(setenv("CUDA_VISIBLE_DEVICES", visible_devices, 1) == 0);
	assert(setenv("CUDA_DEVICE_ORDER", device_order, 1) == 0);
	assert(setenv("CRIU_CUDA_MOCK_UUID_OFFSET", "0", 1) == 0);
	assert(cuda_gpu_inventory_dump() == 0);
	assert(!strcmp(getenv("CUDA_VISIBLE_DEVICES"), visible_devices));
	assert(!strcmp(getenv("CUDA_DEVICE_ORDER"), device_order));

	assert(setenv("CRIU_CUDA_MOCK_UUID_OFFSET", "64", 1) == 0);
	assert(cuda_gpu_inventory_restore_init() == 0);

	check_no_map();
	check_numeric_map();
	check_automatic_map();
	check_uuid_map(uuid_map);
	check_invalid_maps();
	check_without_inventory(uuid_map);

	cuda_gpu_inventory_fini();
	close(image_dir_fd);
	assert(rmdir(directory) == 0);

	return 0;
}
